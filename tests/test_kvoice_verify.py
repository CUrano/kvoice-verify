"""Tests del verificador independiente.

Dos objetivos distintos:

1. **Compatibilidad con el servidor.** Que el verificador acepte lo que la
   API produce de verdad. Se replican aqui la canonicalizacion y el arbol
   Merkle *tal como estan en el backend*; si alguien cambia el backend sin
   cambiar el verificador, estos tests fallan. Es su razon de ser.

2. **Rechazo adversarial.** Un verificador que solo se prueba con entradas
   validas no sirve de nada: lo unico que importa es que diga NO cuando
   toca. Cada manipulacion plausible tiene su test.
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

# Semilla fija: los tests deben ser reproducibles.
SEED = bytes.fromhex(
    "1111111111111111111111111111111111111111111111111111111111111111"
)
SIGNING_KEY = SigningKey(SEED)
PUBKEY_HEX = bytes(SIGNING_KEY.verify_key).hex()

COMMITMENT_HEX = "aa" * 32
VOTING_ID = "3f2504e0-4f89-11d3-9a0c-0305e82c3301"
ISSUED_AT = "2026-08-11T10:00:00+00:00"


@pytest.fixture
def trust(tmp_path: Path) -> dict:
    return {
        "keys": {
            "acta-v1": {"algorithm": "ed25519", "public_key_hex": PUBKEY_HEX},
        },
        "telos": {
            "chain_id": "abcd" * 16,
            "anchor_contract": "icaronutriti",
            "anchors_table": "anchors",
        },
    }


def make_payload(**overrides) -> dict:
    payload = {
        "typ": kv.RECEIPT_TYP,
        "voting_id": VOTING_ID,
        "commitment_hex": COMMITMENT_HEX,
        "issued_at": ISSUED_AT,
    }
    payload.update(overrides)
    return payload


def make_receipt(payload: dict | None = None, **overrides) -> dict:
    payload = payload or make_payload()
    signature = SIGNING_KEY.sign(kv.canonicalize(payload)).signature
    receipt = {
        "signed": True,
        "payload": payload,
        "signature_hex": signature.hex(),
        "signer_kid": "acta-v1",
        "signer_pubkey_hex": PUBKEY_HEX,
    }
    receipt.update(overrides)
    return receipt


# ---------------------------------------------------------------------------
# Compatibilidad con el backend
# ---------------------------------------------------------------------------


def test_canonicalize_coincide_con_el_backend():
    """Replica de `acta_service.canonicalize`. Si divergen, nada verifica."""
    payload = make_payload()
    esperado = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    assert kv.canonicalize(payload) == esperado


def test_canonicalize_ordena_claves_e_ignora_orden_de_entrada():
    a = kv.canonicalize({"b": 1, "a": 2})
    b = kv.canonicalize({"a": 2, "b": 1})
    assert a == b == b'{"a":2,"b":1}'


def test_canonicalize_no_escapa_no_ascii():
    """`ensure_ascii=False` en el servidor: si aqui se escapara, un titulo
    con acentos rompería la firma."""
    assert kv.canonicalize({"t": "elección"}) == '{"t":"elección"}'.encode("utf-8")


def test_hash_leaf_usa_prefijo_de_dominio():
    raw = bytes.fromhex(COMMITMENT_HEX)
    assert kv.hash_leaf(raw) == hashlib.sha256(b"\x00" + raw).digest()


def test_hash_node_usa_prefijo_distinto_al_de_hoja():
    """Sin prefijos distintos, un nodo interno podria pasar por hoja."""
    a, b = b"\x01" * 32, b"\x02" * 32
    assert kv.hash_node(a, b) == hashlib.sha256(b"\x01" + a + b).digest()
    assert kv.hash_node(a, b) != kv.hash_leaf(a + b)


# ---- Merkle: se replica el backend y se comprueba que cuadra -------------


def _backend_root(leaves: list[bytes]) -> bytes:
    """Copia de `merkle.compute_root`, incluida la duplicacion del ultimo."""
    if not leaves:
        return hashlib.sha256(b"kvoice-empty-tree").digest()
    if len(leaves) == 1:
        return leaves[0]
    level = list(leaves)
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        level = [kv.hash_node(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def _backend_proof(leaves: list[bytes], index: int) -> list[tuple[str, bytes]]:
    """Copia de `merkle.build_proof`."""
    steps: list[tuple[str, bytes]] = []
    level = list(leaves)
    pos = index
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        if pos % 2 == 0:
            steps.append(("R", level[pos + 1]))
        else:
            steps.append(("L", level[pos - 1]))
        level = [kv.hash_node(level[i], level[i + 1]) for i in range(0, len(level), 2)]
        pos //= 2
    return steps


@pytest.mark.parametrize("n_hojas", [1, 2, 3, 4, 5, 7, 8, 16, 31])
def test_recompute_root_reproduce_el_arbol_del_backend(n_hojas: int):
    """Incluye tamanos impares, donde el backend duplica el ultimo nodo:
    es el caso que mas facilmente divergiria."""
    leaves = [kv.hash_leaf(bytes([i]) * 32) for i in range(n_hojas)]
    root = _backend_root(leaves)
    for index in range(n_hojas):
        steps = _backend_proof(leaves, index)
        assert kv.recompute_root(leaves[index], steps) == root, f"hoja {index}"


def test_arbol_de_una_hoja_no_tiene_pasos():
    leaf = kv.hash_leaf(b"\x05" * 32)
    assert kv.recompute_root(leaf, []) == leaf


def test_recompute_root_rechaza_lado_invalido():
    leaf = kv.hash_leaf(b"\x01" * 32)
    with pytest.raises(kv.VerifierError):
        kv.recompute_root(leaf, [("X", b"\x02" * 32)])


# ---------------------------------------------------------------------------
# Firma: casos validos
# ---------------------------------------------------------------------------


def test_firma_valida(trust):
    report = kv.Report()
    assert kv.check_signature(make_receipt(), trust, report) is True
    assert report.ok
    assert report.facts["commitment_hex"] == COMMITMENT_HEX


def test_acepta_export_de_la_app():
    """Formato real de `receipt-store.service.ts::toDownloadableJson`."""
    doc = {
        "kvoice_receipt_export": 1,
        "voting_id": VOTING_ID,
        "commitment_hex": COMMITMENT_HEX,
        "signed_receipt": make_receipt(),
        "exported_at": ISSUED_AT,
    }
    assert kv.extract_signed_receipt(doc)["signer_kid"] == "acta-v1"


def test_acepta_recibo_suelto():
    assert kv.extract_signed_receipt(make_receipt())["signer_kid"] == "acta-v1"


def test_rechaza_fichero_que_no_es_recibo():
    with pytest.raises(kv.VerifierError):
        kv.extract_signed_receipt({"cualquier": "cosa"})


# ---------------------------------------------------------------------------
# Firma: casos adversariales
# ---------------------------------------------------------------------------


def test_rechaza_payload_alterado(trust):
    """Se cambia el commitment despues de firmar: el ataque obvio."""
    receipt = make_receipt()
    receipt["payload"]["commitment_hex"] = "bb" * 32
    report = kv.Report()
    assert kv.check_signature(receipt, trust, report) is False


def test_rechaza_issued_at_retocado(trust):
    receipt = make_receipt()
    receipt["payload"]["issued_at"] = "2026-01-01T00:00:00+00:00"
    report = kv.Report()
    assert kv.check_signature(receipt, trust, report) is False


def test_rechaza_firma_con_un_bit_cambiado(trust):
    receipt = make_receipt()
    sig = bytearray(bytes.fromhex(receipt["signature_hex"]))
    sig[0] ^= 0x01
    receipt["signature_hex"] = sig.hex()
    report = kv.Report()
    assert kv.check_signature(receipt, trust, report) is False


def test_rechaza_firma_de_otra_clave(trust):
    """Un operador que firme con una clave distinta de la publicada."""
    otra = SigningKey(bytes.fromhex("22" * 32))
    payload = make_payload()
    receipt = {
        "signed": True,
        "payload": payload,
        "signature_hex": otra.sign(kv.canonicalize(payload)).signature.hex(),
        "signer_kid": "acta-v1",
        "signer_pubkey_hex": PUBKEY_HEX,  # miente sobre con que firmo
    }
    report = kv.Report()
    assert kv.check_signature(receipt, trust, report) is False


def test_rechaza_pubkey_declarada_distinta_de_la_anclada(trust):
    """El nucleo del modelo de confianza: la clave del fichero manda.

    Si el verificador usara la pubkey que viene en el recibo, un operador
    hostil firmaria con la clave que quisiera y adjuntaria su pubkey. Todo
    verificaria y no se demostraria nada.
    """
    otra = SigningKey(bytes.fromhex("33" * 32))
    payload = make_payload()
    receipt = {
        "signed": True,
        "payload": payload,
        "signature_hex": otra.sign(kv.canonicalize(payload)).signature.hex(),
        "signer_kid": "acta-v1",
        "signer_pubkey_hex": bytes(otra.verify_key).hex(),
    }
    report = kv.Report()
    assert kv.check_signature(receipt, trust, report) is False
    assert "NO es la anclada" in report.checks[0].detail


def test_rechaza_kid_desconocido(trust):
    report = kv.Report()
    assert kv.check_signature(make_receipt(signer_kid="acta-v9"), trust, report) is False


def test_rechaza_recibo_sin_firmar(trust):
    """`signed: false`: el servidor lo emite si no tiene clave. Es legitimo
    como documento, pero no prueba nada."""
    report = kv.Report()
    receipt = {"signed": False, "payload": make_payload()}
    assert kv.check_signature(receipt, trust, report) is False


def test_rechaza_typ_de_otro_dominio(trust):
    """Separacion de dominio: la clave firma actas y recibos. Un acta no
    puede colarse como recibo."""
    payload = make_payload(typ="kvoice-acta-v1")
    report = kv.Report()
    assert kv.check_signature(make_receipt(payload), trust, report) is False


def test_rechaza_campos_obligatorios_vacios(trust):
    for campo in ("voting_id", "commitment_hex", "issued_at"):
        payload = make_payload(**{campo: ""})
        report = kv.Report()
        assert kv.check_signature(make_receipt(payload), trust, report) is False, campo


def test_rechaza_campo_extra_inyectado(trust):
    """Anadir un campo al payload cambia el JSON canonico y rompe la firma:
    nadie puede colar datos en un recibo ya emitido."""
    receipt = make_receipt()
    receipt["payload"]["admin"] = True
    report = kv.Report()
    assert kv.check_signature(receipt, trust, report) is False


# ---------------------------------------------------------------------------
# Merkle contra una API simulada
# ---------------------------------------------------------------------------


@pytest.fixture
def api_falsa(monkeypatch):
    """Sustituye la llamada HTTP para no depender de la red."""

    def _install(respuesta: dict):
        monkeypatch.setattr(kv, "http_get_json", lambda url: respuesta)

    return _install


def _proof_response(n_hojas: int, index: int, **overrides) -> dict:
    leaves = [kv.hash_leaf(bytes([i]) * 32) for i in range(n_hojas)]
    leaves[index] = kv.hash_leaf(bytes.fromhex(COMMITMENT_HEX))
    root = _backend_root(leaves)
    steps = _backend_proof(leaves, index)
    data = {
        "commitment_hex": COMMITMENT_HEX,
        "leaf_index": index,
        "leaf_count": n_hojas,
        "batch_index": 7,
        "merkle_root_hex": root.hex(),
        "anchor_backend": "telos",
        "external_block": 100,
        "proof": [{"side": s, "hash_hex": h.hex()} for s, h in steps],
    }
    data.update(overrides)
    return data


def test_merkle_valido(api_falsa):
    api_falsa(_proof_response(8, 3))
    report = kv.Report()
    assert kv.check_merkle(COMMITMENT_HEX, "http://x/v1", report) is not None
    assert report.ok


def test_merkle_rechaza_raiz_que_no_cuadra(api_falsa):
    """La API declara una raiz distinta de la que produce el camino."""
    api_falsa(_proof_response(8, 3, merkle_root_hex="ff" * 32))
    report = kv.Report()
    assert kv.check_merkle(COMMITMENT_HEX, "http://x/v1", report) is None
    assert not report.ok


def test_merkle_rechaza_hermano_manipulado(api_falsa):
    """Cambiar un solo hermano del camino invalida la reconstruccion."""
    data = _proof_response(8, 3)
    data["proof"][0]["hash_hex"] = "cc" * 32
    api_falsa(data)
    report = kv.Report()
    assert kv.check_merkle(COMMITMENT_HEX, "http://x/v1", report) is None


def test_merkle_rechaza_lado_invertido(api_falsa):
    """Invertir L/R produce otra raiz: el orden es parte de la prueba."""
    data = _proof_response(8, 3)
    for step in data["proof"]:
        step["side"] = "L" if step["side"] == "R" else "R"
    api_falsa(data)
    report = kv.Report()
    assert kv.check_merkle(COMMITMENT_HEX, "http://x/v1", report) is None


def test_merkle_rechaza_prueba_de_otro_commitment(api_falsa):
    """Prueba correcta pero de OTRA hoja: no demuestra tu inclusion."""
    leaves = [kv.hash_leaf(bytes([i]) * 32) for i in range(8)]
    data = {
        "leaf_index": 2,
        "leaf_count": 8,
        "batch_index": 7,
        "merkle_root_hex": _backend_root(leaves).hex(),
        "anchor_backend": "telos",
        "proof": [
            {"side": s, "hash_hex": h.hex()} for s, h in _backend_proof(leaves, 2)
        ],
    }
    api_falsa(data)
    report = kv.Report()
    assert kv.check_merkle(COMMITMENT_HEX, "http://x/v1", report) is None


# ---------------------------------------------------------------------------
# Cadena
# ---------------------------------------------------------------------------


@pytest.fixture
def cadena_falsa(monkeypatch):
    """Nodo Telos simulado.

    `get_info` y `get_table_rows` van los dos por POST (como en la API real
    de Antelope), asi que hay que enrutar por URL y no por metodo.
    """

    def _install(chain_id: str, rows: list[dict], lib: int = 1000):
        def _post(url: str, payload: dict):
            if url.endswith("/get_info"):
                return {
                    "chain_id": chain_id,
                    "last_irreversible_block_num": lib,
                }
            if url.endswith("/get_table_rows"):
                return {"rows": rows}
            raise AssertionError(f"llamada inesperada al nodo: {url}")

        monkeypatch.setattr(kv, "http_post_json", _post)

    return _install


def test_cadena_ok_e_irreversible(trust, cadena_falsa):
    root = "ab" * 32
    cadena_falsa("abcd" * 16, [{"batch_index": 7, "merkle_root": root, "leaf_count": 8}])
    report = kv.Report()
    report.facts["merkle_root_hex"] = root
    proof = {
        "anchor_backend": "telos",
        "batch_index": 7,
        "leaf_count": 8,
        "external_block": 500,
    }
    kv.check_onchain(proof, trust, "http://nodo", report)
    assert report.ok


def test_cadena_rechaza_nodo_de_otra_cadena(trust, cadena_falsa):
    """Un nodo de testnet responde igual de bien y no prueba nada."""
    cadena_falsa("0000" * 16, [{"batch_index": 7, "merkle_root": "ab" * 32}])
    report = kv.Report()
    report.facts["merkle_root_hex"] = "ab" * 32
    kv.check_onchain(
        {"anchor_backend": "telos", "batch_index": 7, "external_block": 1},
        trust,
        "http://nodo",
        report,
    )
    assert not report.ok
    assert "no la" in report.checks[0].detail


def test_cadena_rechaza_raiz_distinta_en_la_cadena(trust, cadena_falsa):
    """El caso que de verdad importa: la API dice una cosa y la cadena otra."""
    cadena_falsa("abcd" * 16, [{"batch_index": 7, "merkle_root": "99" * 32}])
    report = kv.Report()
    report.facts["merkle_root_hex"] = "ab" * 32
    kv.check_onchain(
        {"anchor_backend": "telos", "batch_index": 7, "external_block": 1},
        trust,
        "http://nodo",
        report,
    )
    assert not report.ok


def test_cadena_rechaza_lote_ausente(trust, cadena_falsa):
    cadena_falsa("abcd" * 16, [])
    report = kv.Report()
    report.facts["merkle_root_hex"] = "ab" * 32
    kv.check_onchain(
        {"anchor_backend": "telos", "batch_index": 7, "external_block": 1},
        trust,
        "http://nodo",
        report,
    )
    assert not report.ok


def test_cadena_rechaza_backend_local(trust):
    """El modo local es evidencia HMAC del propio operador."""
    report = kv.Report()
    kv.check_onchain({"anchor_backend": "local", "batch_index": 7}, trust, "http://n", report)
    assert not report.ok
    assert "local" in report.checks[0].detail


def test_detecta_leaf_count_incoherente(trust, cadena_falsa):
    """La API dice 8 hojas, la cadena 9: no es el mismo lote."""
    root = "ab" * 32
    cadena_falsa("abcd" * 16, [{"batch_index": 7, "merkle_root": root, "leaf_count": 9}])
    report = kv.Report()
    report.facts["merkle_root_hex"] = root
    kv.check_onchain(
        {
            "anchor_backend": "telos",
            "batch_index": 7,
            "leaf_count": 8,
            "external_block": 500,
        },
        trust,
        "http://nodo",
        report,
    )
    assert not report.ok
    assert any(c.name == "coherencia" and not c.passed for c in report.checks)


def test_avisa_si_aun_es_reversible(trust, cadena_falsa):
    """Anclado no es lo mismo que irreversible."""
    root = "ab" * 32
    cadena_falsa(
        "abcd" * 16,
        [{"batch_index": 7, "merkle_root": root, "leaf_count": 8}],
        lib=100,
    )
    report = kv.Report()
    report.facts["merkle_root_hex"] = root
    kv.check_onchain(
        {
            "anchor_backend": "telos",
            "batch_index": 7,
            "leaf_count": 8,
            "external_block": 500,
        },
        trust,
        "http://nodo",
        report,
    )
    assert not report.ok
    irrev = [c for c in report.checks if c.name == "irreversibilidad"][0]
    assert not irrev.passed


# ---------------------------------------------------------------------------
# Integracion de la CLI
# ---------------------------------------------------------------------------


def test_cli_offline_devuelve_0_con_recibo_valido(tmp_path, monkeypatch):
    keys = tmp_path / "keys.json"
    keys.write_text(
        json.dumps({"keys": {"acta-v1": {"public_key_hex": PUBKEY_HEX}}}),
        encoding="utf-8",
    )
    recibo = tmp_path / "recibo.json"
    recibo.write_text(json.dumps({"signed_receipt": make_receipt()}), encoding="utf-8")

    codigo = kv.main([str(recibo), "--offline", "--keys", str(keys)])
    assert codigo == 0


def test_cli_offline_devuelve_1_con_recibo_manipulado(tmp_path):
    keys = tmp_path / "keys.json"
    keys.write_text(
        json.dumps({"keys": {"acta-v1": {"public_key_hex": PUBKEY_HEX}}}),
        encoding="utf-8",
    )
    receipt = make_receipt()
    receipt["payload"]["commitment_hex"] = "ff" * 32
    recibo = tmp_path / "recibo.json"
    recibo.write_text(json.dumps({"signed_receipt": receipt}), encoding="utf-8")

    assert kv.main([str(recibo), "--offline", "--keys", str(keys)]) == 1


def test_cli_devuelve_2_si_el_fichero_no_existe(tmp_path):
    assert kv.main([str(tmp_path / "no_existe.json"), "--offline"]) == 2


def test_cli_devuelve_2_si_el_json_es_invalido(tmp_path):
    malo = tmp_path / "malo.json"
    malo.write_text("{esto no es json", encoding="utf-8")
    assert kv.main([str(malo), "--offline"]) == 2


def test_claves_ancladas_del_repo_son_validas():
    """El trusted_keys.json que se distribuye debe ser usable."""
    trust = kv.load_trust(kv.DEFAULT_KEYS_FILE)
    assert "acta-v1" in trust["keys"]
    pub = trust["keys"]["acta-v1"]["public_key_hex"]
    assert len(bytes.fromhex(pub)) == 32
    assert len(bytes.fromhex(trust["telos"]["chain_id"])) == 32
