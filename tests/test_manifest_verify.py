"""Tests de la verificacion de manifests multi-firma.

Mismos dos objetivos que el verificador de recibos:

1. **Compatibilidad con el servidor.** Se replica aqui la canonicalizacion
   del manifest *tal como esta en `manifest_service.canonical_bytes`*
   (`ensure_ascii=True`, distinta de la del recibo) y la construccion de
   `manifest_full`. Si el backend cambia sin cambiar el verificador,
   estos tests fallan.

2. **Rechazo adversarial.** Cada manipulacion plausible tiene su test:
   contenido alterado, hash declarado falso, clave de custodio ajena,
   firma duplicada, umbral incompleto, firma sobre el mensaje equivocado,
   raiz ausente en la cadena, anclaje aun reversible...
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest
from nacl.signing import SigningKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import kvoice_verify as kv  # noqa: E402

# Semillas fijas: los tests deben ser reproducibles.
SERVER_KEY = SigningKey(bytes.fromhex("11" * 32))
SERVER_PUB = bytes(SERVER_KEY.verify_key).hex()
ORGANIZER_KEY = SigningKey(bytes.fromhex("44" * 32))
ORGANIZER_PUB = bytes(ORGANIZER_KEY.verify_key).hex()
CUSTODIAN_KEYS = [SigningKey(bytes([0x50 + i]) * 32) for i in range(3)]

VOTING_ID = "3f2504e0-4f89-11d3-9a0c-0305e82c3301"
TENANT_ID = "9b2b7bd2-59e5-4b52-8b0a-2f3f7a1c0001"
ISO = "2026-08-20T09:00:00+00:00"
CHAIN_ID = "abcd" * 16


@pytest.fixture
def trust() -> dict:
    return {
        "keys": {
            "acta-v1": {"algorithm": "ed25519", "public_key_hex": SERVER_PUB},
        },
        "telos": {
            "chain_id": CHAIN_ID,
            "anchor_contract": "icaronutriti",
            "anchors_table": "anchors",
        },
    }


# ---------------------------------------------------------------------------
# Constructores que replican al backend
# ---------------------------------------------------------------------------


def backend_canonical(obj) -> bytes:
    """Replica de `manifest_service.canonical_bytes`. Si divergen, nada
    verifica."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def make_payload(secret: bool = True, n: int = 3, k: int = 2, **definition_overrides) -> dict:
    """Manifest (capa 1) con la misma forma que `build_manifest`."""
    definition = {
        "voting_id": VOTING_ID,
        "tenant_id": TENANT_ID,
        "title": "Elección de junta",  # no-ASCII a proposito: ejercita ensure_ascii
        "description": None,
        "voting_type": "single_choice",
        "visibility": "private",
        "secret_ballot": secret,
        "kyc_required": False,
        "opens_at": "2026-08-20T10:00:00+00:00",
        "closes_at": "2026-08-21T10:00:00+00:00",
        "quorum_mode": "none",
        "quorum_value": None,
        "majority_rule": "simple",
        "majority_custom_percent": None,
        "questions": [],
        "options": [
            {"id": "opt-1", "label": "Sí", "position": 0},
            {"id": "opt-2", "label": "No", "position": 1},
        ],
    }
    definition.update(definition_overrides)
    crypto = None
    if secret:
        crypto = {
            "algorithm": "x25519-sealedbox-shamir",
            "session_pubkey_hex": "cd" * 32,
            "threshold_k": k,
            "threshold_n": n,
            "custodians": [
                {
                    "holder_index": i + 1,
                    "x25519_pubkey_sha256_hex": hashlib.sha256(
                        bytes([i]) * 32
                    ).hexdigest(),
                    "ed25519_pubkey_hex": bytes(
                        CUSTODIAN_KEYS[i].verify_key
                    ).hex(),
                    "share_commitment_hex": hashlib.sha256(
                        b"share" + bytes([i])
                    ).hexdigest(),
                }
                for i in range(n)
            ],
        }
    return {
        "protocol": kv.MANIFEST_PROTOCOL,
        "definition": definition,
        "census": {"policy": "private", "root_hex": "ab" * 32, "eligible_count": 12},
        "crypto": crypto,
        "meta": {
            "backend_version": "0.1.51",
            "anchor_policy": "manifest anclado antes del primer token de voto",
            "created_at": ISO,
        },
    }


def manifest_hash(payload: dict) -> bytes:
    return hashlib.sha256(backend_canonical(payload)).digest()


def make_full(
    payload: dict,
    *,
    with_server: bool = True,
    with_organizer: bool = True,
    n_custodians: int | None = None,
    server_kid: str = "acta-v1",
) -> dict:
    """`manifest_full` (capa 2) como lo compila `_finalize_and_anchor`:
    payload + bloque `signatures`, todas las firmas sobre los BYTES del
    hash."""
    m_hash = manifest_hash(payload)
    crypto = payload.get("crypto")
    if n_custodians is None:
        n_custodians = int(crypto["threshold_n"]) if crypto else 0
    signatures: dict = {"server": None, "organizer": None, "custodians": []}
    if with_server:
        signatures["server"] = {
            "signer_kid": server_kid,
            "pubkey_hex": SERVER_PUB,
            "signature_hex": SERVER_KEY.sign(m_hash).signature.hex(),
            "signed_at": ISO,
        }
    if with_organizer:
        signatures["organizer"] = {
            "user_id": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
            "pubkey_hex": ORGANIZER_PUB,
            "signature_hex": ORGANIZER_KEY.sign(m_hash).signature.hex(),
            "signed_at": ISO,
        }
    for i in range(n_custodians):
        key = CUSTODIAN_KEYS[i]
        signatures["custodians"].append(
            {
                "key_holder_id": f"00000000-0000-0000-0000-00000000000{i}",
                "pubkey_hex": bytes(key.verify_key).hex(),
                "signature_hex": key.sign(m_hash).signature.hex(),
                "signed_at": ISO,
            }
        )
    return {**payload, "signatures": signatures}


def make_wrapper(full: dict, **overrides) -> dict:
    """Respuesta de `GET /votings/{id}/manifest` (VotingManifestRead)."""
    payload = {klave: v for klave, v in full.items() if klave != "signatures"}
    doc = {
        "voting_id": VOTING_ID,
        "protocol_version": kv.MANIFEST_PROTOCOL,
        "manifest": payload,
        "manifest_hash_hex": manifest_hash(payload).hex(),
        "definition_hash_hex": hashlib.sha256(
            backend_canonical(payload["definition"])
        ).hexdigest(),
        "census_root_hex": "ab" * 32,
        "eligible_count": 12,
        "signature_hex": full["signatures"]["server"]["signature_hex"]
        if full["signatures"]["server"]
        else None,
        "signer_kid": "acta-v1",
        "signer_pubkey_hex": SERVER_PUB,
        "anchor_backend": "telos",
        "anchor_tx_id": "f9" * 32,
        "anchored_at": ISO,
        "signature_state": "anchored",
        "manifest_full": full,
        "signatures_collected": None,
        "signatures_required": None,
    }
    doc.update(overrides)
    return doc


def run_offline(doc: dict, trust: dict) -> kv.Report:
    """Hash + firmas, sin red (lo que hace `main` para un manifest)."""
    report = kv.Report()
    payload, signatures, wrapper_payload, declared = kv.extract_manifest(doc)
    m_hash = kv.check_manifest_hash(payload, wrapper_payload, declared, report)
    if m_hash is not None:
        kv.check_manifest_signatures(m_hash, payload, signatures, trust, report)
    return report


# ---------------------------------------------------------------------------
# Compatibilidad con el backend
# ---------------------------------------------------------------------------


def test_canonical_ascii_coincide_con_el_backend():
    payload = make_payload()
    assert kv.canonicalize_ascii(payload) == backend_canonical(payload)


def test_canonical_ascii_escapa_no_ascii_a_diferencia_del_recibo():
    """El manifest usa `ensure_ascii=True` y el recibo `False`. Confundir
    las dos canonicalizaciones romperia TODAS las firmas."""
    doc = {"t": "elección"}
    assert kv.canonicalize_ascii(doc) == b'{"t":"elecci\\u00f3n"}'
    assert kv.canonicalize(doc) == '{"t":"elección"}'.encode("utf-8")
    assert kv.canonicalize_ascii(doc) != kv.canonicalize(doc)


def test_hash_es_sha256_del_canonico():
    payload = make_payload()
    assert manifest_hash(payload) == hashlib.sha256(
        kv.canonicalize_ascii(payload)
    ).digest()


# ---------------------------------------------------------------------------
# Deteccion y extraccion
# ---------------------------------------------------------------------------


def test_detecta_recibo_y_manifest():
    assert kv.detect_document({"payload": {}, "signature_hex": "00"}) == "receipt"
    assert kv.detect_document({"signed_receipt": {}}) == "receipt"
    assert kv.detect_document(make_wrapper(make_full(make_payload()))) == "manifest"
    assert kv.detect_document(make_full(make_payload())) == "manifest"


def test_rechaza_documento_desconocido():
    with pytest.raises(kv.VerifierError):
        kv.detect_document({"cualquier": "cosa"})


def test_rechaza_manifest_awaiting_signatures():
    """Sin `manifest_full` no hay firmas: hay que decirlo, no verificar a
    medias."""
    doc = make_wrapper(make_full(make_payload()))
    doc["manifest_full"] = None
    doc["signature_state"] = "awaiting_signatures"
    with pytest.raises(kv.VerifierError, match="aun no esta anclado"):
        kv.extract_manifest(doc)


def test_rechaza_manifest_sin_bloque_de_firmas():
    with pytest.raises(kv.VerifierError, match="signatures"):
        kv.extract_manifest(make_payload())


# ---------------------------------------------------------------------------
# Hash: casos validos y adversariales
# ---------------------------------------------------------------------------


def test_manifest_valido_con_envoltorio(trust):
    report = run_offline(make_wrapper(make_full(make_payload())), trust)
    assert report.ok
    assert report.facts["voting_id"] == VOTING_ID
    assert report.facts["manifest_hash_hex"] == manifest_hash(make_payload()).hex()


def test_manifest_valido_suelto_sin_envoltorio(trust):
    """Un auditor puede tener solo `manifest_full`."""
    report = run_offline(make_full(make_payload()), trust)
    assert report.ok


def test_hash_declarado_distinto_falla(trust):
    doc = make_wrapper(make_full(make_payload()))
    doc["manifest_hash_hex"] = "ff" * 32
    report = run_offline(doc, trust)
    assert not report.ok
    assert any(c.name == "hash" and not c.passed for c in report.checks)


def test_envoltorio_con_manifest_divergente_falla(trust):
    """`manifest` y `manifest_full` deben ser el mismo contenido."""
    doc = make_wrapper(make_full(make_payload()))
    doc["manifest"] = json.loads(json.dumps(doc["manifest"]))
    doc["manifest"]["definition"]["title"] = "Otro título"
    report = run_offline(doc, trust)
    assert any(c.name == "coherencia" and not c.passed for c in report.checks)


def test_definition_hash_declarado_incoherente_falla(trust):
    doc = make_wrapper(make_full(make_payload()))
    doc["definition_hash_hex"] = "ee" * 32
    report = run_offline(doc, trust)
    assert any(c.name == "definicion" and not c.passed for c in report.checks)


def test_protocol_desconocido_falla(trust):
    payload = make_payload()
    payload["protocol"] = "kvoice-manifest-v9"
    full = make_full(payload)
    report = kv.Report()
    p, s, w, d = kv.extract_manifest(full)
    assert kv.check_manifest_hash(p, w, d, report) is None
    assert not report.ok


def test_contenido_alterado_tras_firmar_rompe_todo(trust):
    """El ataque central de P0-07: editar la definicion despues de que la
    firmaran. El hash recalculado cambia y ninguna firma verifica."""
    full = make_full(make_payload())
    full["definition"]["title"] = "Elección de junta (enmendada)"
    report = run_offline(full, trust)
    assert not report.ok
    for nombre in ("firma servidor", "firma organizador", "firmas custodios"):
        assert any(
            c.name == nombre and not c.passed for c in report.checks
        ), nombre


# ---------------------------------------------------------------------------
# Firmas: servidor
# ---------------------------------------------------------------------------


def test_kid_desconocido_falla(trust):
    full = make_full(make_payload(), server_kid="acta-v9")
    report = run_offline(full, trust)
    assert any(c.name == "firma servidor" and not c.passed for c in report.checks)


def test_pubkey_servidor_distinta_de_la_anclada_falla(trust):
    """La clave del fichero manda; la del documento solo delata el engano."""
    otra = SigningKey(bytes.fromhex("77" * 32))
    payload = make_payload()
    full = make_full(payload)
    m_hash = manifest_hash(payload)
    full["signatures"]["server"] = {
        "signer_kid": "acta-v1",
        "pubkey_hex": bytes(otra.verify_key).hex(),
        "signature_hex": otra.sign(m_hash).signature.hex(),
        "signed_at": ISO,
    }
    report = run_offline(full, trust)
    falla = [c for c in report.checks if c.name == "firma servidor"][0]
    assert not falla.passed
    assert "NO es la anclada" in falla.detail


def test_firma_servidor_sobre_json_en_vez_del_hash_falla(trust):
    """Confusion de mensaje: el recibo firma el JSON canonico, el manifest
    firma los 32 bytes del hash. Una firma sobre el JSON no debe colar."""
    payload = make_payload()
    full = make_full(payload)
    full["signatures"]["server"]["signature_hex"] = SERVER_KEY.sign(
        kv.canonicalize_ascii(payload)
    ).signature.hex()
    report = run_offline(full, trust)
    assert any(c.name == "firma servidor" and not c.passed for c in report.checks)


def test_falta_firma_servidor_falla(trust):
    full = make_full(make_payload(), with_server=False)
    report = run_offline(full, trust)
    assert any(c.name == "firma servidor" and not c.passed for c in report.checks)


# ---------------------------------------------------------------------------
# Firmas: organizador
# ---------------------------------------------------------------------------


def test_falta_organizador_con_custodios_falla(trust):
    full = make_full(make_payload(), with_organizer=False)
    report = run_offline(full, trust)
    assert any(
        c.name == "firma organizador" and not c.passed for c in report.checks
    )


def test_server_only_sin_custodios_pasa_con_nota(trust):
    """Votacion no secreta: el backend ancla con solo la firma del servidor
    (regimen server-only documentado). No es un fallo del documento."""
    full = make_full(make_payload(secret=False), with_organizer=False)
    report = run_offline(full, trust)
    assert report.ok
    nota = [c for c in report.checks if c.name == "firma organizador"][0]
    assert "server-only" in nota.detail


def test_firma_organizador_invalida_falla(trust):
    full = make_full(make_payload())
    sig = bytearray(bytes.fromhex(full["signatures"]["organizer"]["signature_hex"]))
    sig[0] ^= 0x01
    full["signatures"]["organizer"]["signature_hex"] = sig.hex()
    report = run_offline(full, trust)
    assert any(
        c.name == "firma organizador" and not c.passed for c in report.checks
    )


def test_organizador_valido_se_reporta_como_no_anclado(trust):
    """Manifest anterior a 0055 (sin bloque `organizer` en el payload): la
    firma solo puede verificarse con la clave declarada y el informe debe
    decirlo en vez de venderlo como garantia."""
    report = run_offline(make_full(make_payload()), trust)
    org = [c for c in report.checks if c.name == "firma organizador"][0]
    assert org.passed
    assert "NO anclada" in org.trust


# ---------------------------------------------------------------------------
# Firmas: organizador con clave anclada en el payload (0055)
# ---------------------------------------------------------------------------


def payload_with_anchored_org(**kw) -> dict:
    """Payload 0055: bloque `organizer` DENTRO del contenido anclado."""
    payload = make_payload(**kw)
    payload["organizer"] = {"ed25519_pubkey_hex": ORGANIZER_PUB}
    return payload


def test_organizador_anclado_valido_pasa(trust):
    report = run_offline(make_full(payload_with_anchored_org()), trust)
    assert report.ok
    org = [c for c in report.checks if c.name == "firma organizador"][0]
    assert org.passed
    assert "DENTRO del contenido" in org.detail
    assert "anclada dentro del contenido" in org.trust


def test_organizador_anclado_clave_declarada_distinta_falla(trust):
    """El bloque de firmas declara otra pubkey que la anclada: la anclada
    manda y la discrepancia es un fallo, no una advertencia."""
    full = make_full(payload_with_anchored_org())
    otra = SigningKey(bytes.fromhex("55" * 32))
    full["signatures"]["organizer"]["pubkey_hex"] = bytes(otra.verify_key).hex()
    report = run_offline(full, trust)
    assert any(
        c.name == "firma organizador" and not c.passed for c in report.checks
    )


def test_organizador_anclado_firma_de_impostor_falla(trust):
    """Firma de otra clave aunque declare la pubkey anclada correcta."""
    payload = payload_with_anchored_org()
    full = make_full(payload)
    impostor = SigningKey(bytes.fromhex("66" * 32))
    full["signatures"]["organizer"]["signature_hex"] = impostor.sign(
        manifest_hash(payload)
    ).signature.hex()
    report = run_offline(full, trust)
    assert any(
        c.name == "firma organizador" and not c.passed for c in report.checks
    )


def test_organizador_anclado_sustituir_clave_rompe_hash(trust):
    """Editar la clave anclada del payload cambia el hash: el envoltorio
    (que declara el hash original) deja de cuadrar. Esta es exactamente la
    garantia que motiva anclar la clave."""
    full = make_full(payload_with_anchored_org())
    doc = make_wrapper(full)
    otra = SigningKey(bytes.fromhex("77" * 32))
    doc["manifest_full"]["organizer"] = {
        "ed25519_pubkey_hex": bytes(otra.verify_key).hex()
    }
    report = run_offline(doc, trust)
    assert any(c.name == "hash" and not c.passed for c in report.checks)


def test_organizador_bloque_anclado_corrupto_falla_sin_downgrade(trust):
    """Bloque `organizer` presente pero invalido: fallo explicito y sin
    caer al regimen legacy de clave declarada (seria un downgrade)."""
    payload = make_payload()
    payload["organizer"] = {"ed25519_pubkey_hex": "zz" * 32}
    full = make_full(payload)
    report = run_offline(full, trust)
    entradas = [c for c in report.checks if c.name == "firma organizador"]
    assert len(entradas) == 1
    assert not entradas[0].passed


def test_organizador_anclado_sin_firma_falla(trust):
    full = make_full(payload_with_anchored_org(), with_organizer=False)
    report = run_offline(full, trust)
    org = [c for c in report.checks if c.name == "firma organizador"][0]
    assert not org.passed
    assert "falta su firma" in org.detail


# ---------------------------------------------------------------------------
# Firmas: custodios
# ---------------------------------------------------------------------------


def test_firma_custodio_con_clave_ajena_falla(trust):
    """Una firma valida de una clave que no esta en `crypto.custodians` no
    cuenta: las claves legitimas son las del contenido anclado."""
    payload = make_payload()
    full = make_full(payload)
    intruso = SigningKey(bytes.fromhex("99" * 32))
    full["signatures"]["custodians"][2] = {
        "key_holder_id": "00000000-0000-0000-0000-000000000009",
        "pubkey_hex": bytes(intruso.verify_key).hex(),
        "signature_hex": intruso.sign(manifest_hash(payload)).signature.hex(),
        "signed_at": ISO,
    }
    report = run_offline(full, trust)
    falla = [c for c in report.checks if c.name == "firmas custodios"][0]
    assert not falla.passed
    assert "NO es ninguna de" in falla.detail


def test_firma_custodio_duplicada_no_suma_para_el_umbral(trust):
    """El mismo custodio firmando dos veces no puede sustituir a otro."""
    full = make_full(make_payload())
    full["signatures"]["custodians"][2] = dict(full["signatures"]["custodians"][0])
    report = run_offline(full, trust)
    falla = [c for c in report.checks if c.name == "firmas custodios"][0]
    assert not falla.passed
    assert "duplicada" in falla.detail


def test_faltan_firmas_de_custodios_falla(trust):
    full = make_full(make_payload(), n_custodians=2)
    report = run_offline(full, trust)
    falla = [c for c in report.checks if c.name == "firmas custodios"][0]
    assert not falla.passed
    assert "2 de 3" in falla.detail


def test_firma_custodio_con_bit_cambiado_falla(trust):
    full = make_full(make_payload())
    sig = bytearray(
        bytes.fromhex(full["signatures"]["custodians"][1]["signature_hex"])
    )
    sig[0] ^= 0x01
    full["signatures"]["custodians"][1]["signature_hex"] = sig.hex()
    report = run_offline(full, trust)
    assert any(c.name == "firmas custodios" and not c.passed for c in report.checks)


def test_firmas_de_custodio_sin_crypto_es_incoherente(trust):
    """Un manifest sin custodios no puede traer firmas de custodio."""
    payload = make_payload(secret=False)
    full = make_full(payload)
    m_hash = manifest_hash(payload)
    key = CUSTODIAN_KEYS[0]
    full["signatures"]["custodians"] = [
        {
            "key_holder_id": "00000000-0000-0000-0000-000000000000",
            "pubkey_hex": bytes(key.verify_key).hex(),
            "signature_hex": key.sign(m_hash).signature.hex(),
            "signed_at": ISO,
        }
    ]
    report = run_offline(full, trust)
    assert any(c.name == "firmas custodios" and not c.passed for c in report.checks)


# ---------------------------------------------------------------------------
# Cadena
# ---------------------------------------------------------------------------


@pytest.fixture
def cadena_falsa(monkeypatch):
    """Nodo Telos simulado para manifests: get_info + get_table_rows +
    get_block, enrutado por URL."""

    def _install(
        chain_id: str,
        rows: list[dict],
        lib_timestamp: str = "2026-08-20T10:00:00.000",
        more_first: bool = False,
        primary_pages: list[dict] | None = None,
    ):
        pages = list(primary_pages or [])

        def _post(url: str, payload: dict):
            if url.endswith("/get_info"):
                return {"chain_id": chain_id, "last_irreversible_block_num": 1000}
            if url.endswith("/get_table_rows"):
                if payload.get("index_position") == 2:
                    return {"rows": rows, "more": more_first}
                return pages.pop(0)
            if url.endswith("/get_block"):
                return {"timestamp": lib_timestamp}
            raise AssertionError(f"llamada inesperada al nodo: {url}")

        monkeypatch.setattr(kv, "http_post_json", _post)

    return _install


def _row(m_hash_hex: str, **overrides) -> dict:
    row = {
        "id": 3,
        "batch_index": 0,
        "merkle_root": m_hash_hex,
        "leaf_count": 1,
        "anchored_at": "2026-08-20T09:00:00",
    }
    row.update(overrides)
    return row


def test_cadena_ok_e_irreversible(trust, cadena_falsa):
    m_hash_hex = manifest_hash(make_payload()).hex()
    cadena_falsa(CHAIN_ID, [_row(m_hash_hex)])
    report = kv.Report()
    kv.check_manifest_onchain(m_hash_hex, {"anchor_backend": "telos"}, trust, "http://nodo", report)
    assert report.ok
    assert report.facts["onchain_row_id"] == 3


def test_cadena_hash_ausente_falla(trust, cadena_falsa):
    m_hash_hex = manifest_hash(make_payload()).hex()
    cadena_falsa(CHAIN_ID, [_row("99" * 32)])
    report = kv.Report()
    kv.check_manifest_onchain(m_hash_hex, {}, trust, "http://nodo", report)
    assert not report.ok


def test_cadena_leaf_count_distinto_de_1_falla(trust, cadena_falsa):
    """Un manifest siempre se ancla con leaf_count = 1."""
    m_hash_hex = manifest_hash(make_payload()).hex()
    cadena_falsa(CHAIN_ID, [_row(m_hash_hex, leaf_count=8)])
    report = kv.Report()
    kv.check_manifest_onchain(m_hash_hex, {}, trust, "http://nodo", report)
    assert any(c.name == "coherencia" and not c.passed for c in report.checks)


def test_cadena_rechaza_nodo_de_otra_cadena(trust, cadena_falsa):
    m_hash_hex = manifest_hash(make_payload()).hex()
    cadena_falsa("0000" * 16, [_row(m_hash_hex)])
    report = kv.Report()
    kv.check_manifest_onchain(m_hash_hex, {}, trust, "http://nodo", report)
    assert not report.ok


def test_cadena_avisa_si_aun_es_reversible(trust, cadena_falsa):
    """`anchored_at` posterior al timestamp del ultimo bloque irreversible."""
    m_hash_hex = manifest_hash(make_payload()).hex()
    cadena_falsa(
        CHAIN_ID,
        [_row(m_hash_hex, anchored_at="2026-08-20T10:00:30")],
        lib_timestamp="2026-08-20T10:00:00.000",
    )
    report = kv.Report()
    kv.check_manifest_onchain(m_hash_hex, {}, trust, "http://nodo", report)
    irrev = [c for c in report.checks if c.name == "irreversibilidad"][0]
    assert not irrev.passed


def test_backend_local_declarado_falla_sin_red(trust):
    report = kv.Report()
    kv.check_manifest_onchain(
        "ab" * 32, {"anchor_backend": "local"}, trust, "http://nodo", report
    )
    assert not report.ok
    assert "local" in report.checks[0].detail


def test_paginacion_cae_a_escaneo_primario(trust, cadena_falsa):
    """Con >1000 manifests el indice `bybatch` no pagina entre claves
    iguales: el verificador debe caer al escaneo por clave primaria y
    filtrar batch 0."""
    m_hash_hex = manifest_hash(make_payload()).hex()
    cadena_falsa(
        CHAIN_ID,
        rows=[_row("11" * 32, id=1)],
        more_first=True,
        primary_pages=[
            {
                "rows": [
                    _row("11" * 32, id=1),
                    {"id": 2, "batch_index": 7, "merkle_root": "22" * 32,
                     "leaf_count": 9, "anchored_at": "2026-08-20T08:00:00"},
                ],
                "more": True,
                "next_key": "3",
            },
            {"rows": [_row(m_hash_hex, id=3)], "more": False},
        ],
    )
    rows = kv.fetch_manifest_anchor_rows("http://nodo", trust["telos"])
    assert [r["id"] for r in rows] == [1, 3]
    assert all(r["batch_index"] == 0 for r in rows)


# ---------------------------------------------------------------------------
# Integracion de la CLI
# ---------------------------------------------------------------------------


def _write_keys(tmp_path: Path) -> Path:
    keys = tmp_path / "keys.json"
    keys.write_text(
        json.dumps(
            {
                "keys": {"acta-v1": {"public_key_hex": SERVER_PUB}},
                "telos": {"chain_id": CHAIN_ID, "anchor_contract": "icaronutriti"},
            }
        ),
        encoding="utf-8",
    )
    return keys


def test_cli_manifest_offline_valido_devuelve_0(tmp_path):
    keys = _write_keys(tmp_path)
    doc = tmp_path / "manifest.json"
    doc.write_text(
        json.dumps(make_wrapper(make_full(make_payload())), ensure_ascii=False),
        encoding="utf-8",
    )
    assert kv.main([str(doc), "--offline", "--keys", str(keys)]) == 0


def test_cli_manifest_manipulado_devuelve_1(tmp_path):
    keys = _write_keys(tmp_path)
    wrapper = make_wrapper(make_full(make_payload()))
    wrapper["manifest_full"]["definition"]["title"] = "Otra cosa"
    doc = tmp_path / "manifest.json"
    doc.write_text(json.dumps(wrapper, ensure_ascii=False), encoding="utf-8")
    assert kv.main([str(doc), "--offline", "--keys", str(keys)]) == 1


def test_cli_manifest_awaiting_devuelve_2(tmp_path):
    keys = _write_keys(tmp_path)
    wrapper = make_wrapper(make_full(make_payload()))
    wrapper["manifest_full"] = None
    wrapper["signature_state"] = "awaiting_signatures"
    doc = tmp_path / "manifest.json"
    doc.write_text(json.dumps(wrapper, ensure_ascii=False), encoding="utf-8")
    assert kv.main([str(doc), "--offline", "--keys", str(keys)]) == 2
