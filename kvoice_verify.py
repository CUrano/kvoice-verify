#!/usr/bin/env python3
"""Verificador independiente de recibos de voto y manifests de KVoice (P1-01).

QUE PROBLEMA CIERRA
===================

KVoice emite un recibo firmado por cada voto, agrupa los commitments en
un arbol Merkle y ancla la raiz en Telos. Hasta ahora esas garantias solo
se podian comprobar **preguntandole a KVoice**: el propio fichero que
exporta la app dice «haz POST a /v1/verify/receipt». Eso es circular. Si
el operador miente, tambien miente el endpoint con el que lo compruebas.

Este programa rompe el circulo. Comprueba lo comprobable **sin conceder
autoridad a KVoice en ningun paso critico**:

    Paso                     Fuente de verdad          KVoice puede mentir?
    ---------------------------------------------------------------------
    1. Firma Ed25519         clave anclada en disco     NO
    2. Prueba Merkle         la aporta KVoice...        NO (*)
    3. Raiz en la cadena     nodo publico de Telos      NO
    4. Irreversibilidad      nodo publico de Telos      NO

    (*) La prueba la sirve KVoice, pero es autoverificable: se recalcula
        la raiz partiendo del commitment del recibo. Una prueba falsa da
        una raiz que no coincide con la que esta en la cadena.

Lo que este programa NO puede comprobar, y conviene tener claro:

  - Que el censo fuese legitimo, ni que no se admitieran votantes de mas.
  - Que TODOS los votos emitidos esten incluidos (verificabilidad
    universal). Esto demuestra inclusion del recibo que le das, no
    completitud del recuento.
  - Que el recuento corresponda a los votos cifrados. Eso exige el
    recuento homomorfico con pruebas Chaum-Pedersen, que no existe aun
    (ver CRYPTOGRAPHIC_REVIEW.md §6).

Es decir: demuestra **verificabilidad individual**, no universal. Quien
diga lo contrario esta vendiendo humo.

MANIFESTS (P0-07)
=================

Ademas de recibos, verifica el **manifest electoral multi-firma**: el
documento que fija la definicion de la votacion (preguntas, censo,
custodios, umbral k-de-n, commitments de las shares) antes de abrirse.
Lo firman servidor + organizador + N custodios y su hash se ancla en
Telos con `batch_index = 0` (reservado para manifests).

    Comprobacion                     Fuente de verdad
    ------------------------------------------------------------------
    1. Hash del contenido            recalculado aqui
    2. Firma del servidor            clave anclada en disco
    3. Firmas de los N custodios     claves DENTRO del contenido anclado (*)
    4. Firma del organizador         clave declarada en el documento
    5. Hash en la cadena             nodo publico de Telos
    6. Irreversibilidad              nodo publico de Telos

    (*) Las pubkeys Ed25519 de los custodios forman parte del payload
        cuyo hash esta en la cadena: sustituir una cambia el hash y el
        anclaje deja de cuadrar. La del organizador NO esta en el payload:
        se verifica con la clave que declara el propio documento, asi que
        identifica al organizador solo si esa clave se conoce por otra
        via. El informe lo dice explicitamente.

El fichero de entrada es la respuesta JSON de
`GET /v1/votings/{id}/manifest` (o su campo `manifest_full` suelto).
El tipo de documento (recibo o manifest) se detecta solo.

USO
===

    python kvoice_verify.py recibo.json
    python kvoice_verify.py manifest.json
    python kvoice_verify.py documento.json --offline   # sin red
    python kvoice_verify.py documento.json --json      # salida automatizable

Codigos de salida: 0 todo correcto, 1 alguna comprobacion falla,
2 error de uso o de red (no es un fallo de verificacion).

DEPENDENCIAS
============

Solo PyNaCl, para Ed25519. El resto es libreria estandar a proposito: un
verificador con muchas dependencias es un verificador que nadie audita.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from nacl.exceptions import BadSignatureError
    from nacl.signing import VerifyKey
except ImportError:  # pragma: no cover
    sys.stderr.write(
        "Falta PyNaCl. Instalalo con:  pip install -r requirements.txt\n"
    )
    raise SystemExit(2)

DEFAULT_API_URL = "https://api.kvoice.org.es/v1"
DEFAULT_TELOS_NODE = "https://mainnet.telos.net"
DEFAULT_KEYS_FILE = Path(__file__).with_name("trusted_keys.json")

#: Discriminador de dominio del recibo. Un acta firmada con la MISMA clave
#: no debe poder presentarse como recibo, de ahi que se exija el valor
#: exacto (kvoice_api/services/receipt_service.py: RECEIPT_TYP).
RECEIPT_TYP = "kvoice-receipt-v1"

#: Protocolo del manifest electoral (manifest_service.PROTOCOL_VERSION).
MANIFEST_PROTOCOL = "kvoice-manifest-v1"

#: batch_index reservado para manifests en el contrato de anclaje. Los
#: lotes Merkle de votos usan indices >= 1 (kvoiceanchor.hpp).
MANIFEST_BATCH_INDEX = 0

#: Prefijos de dominio del arbol Merkle (kvoice_api/anchor/merkle.py).
#: Sin ellos, un nodo interno podria hacerse pasar por hoja (segunda
#: preimagen).
LEAF_DOMAIN = b"\x00"
NODE_DOMAIN = b"\x01"

HTTP_TIMEOUT = 20

#: Sin User-Agent propio, los nodos publicos de Telos responden 403: el
#: agente por defecto de urllib (`Python-urllib/3.x`) esta bloqueado en los
#: endpoints tras CDN. Verificado contra mainnet.telos.net el 11/08/2026.
USER_AGENT = "kvoice-verify/1.0 (+https://github.com/CUrano/kvoice)"


# ---------------------------------------------------------------------------
# Resultado
# ---------------------------------------------------------------------------


@dataclass
class Check:
    name: str
    passed: bool
    detail: str
    trust: str = ""


@dataclass
class Report:
    checks: list[Check] = field(default_factory=list)
    facts: dict[str, Any] = field(default_factory=dict)

    def add(self, name: str, passed: bool, detail: str, trust: str = "") -> bool:
        self.checks.append(Check(name, passed, detail, trust))
        return passed

    @property
    def ok(self) -> bool:
        return all(c.passed for c in self.checks)


class VerifierError(Exception):
    """Error de uso, de red o de datos: no es un fallo de verificacion."""


# ---------------------------------------------------------------------------
# Primitivas
# ---------------------------------------------------------------------------


def canonicalize(payload: dict[str, Any]) -> bytes:
    """JSON canonico, byte a byte igual que el del servidor.

    Debe coincidir EXACTAMENTE con `kvoice_api.services.acta_service
    .canonicalize`, o ninguna firma verificara: `sort_keys=True`,
    separadores sin espacios y `ensure_ascii=False` (los no-ASCII van como
    UTF-8, no escapados).
    """
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def canonicalize_ascii(payload: Any) -> bytes:
    """JSON canonico del MANIFEST, byte a byte igual que el del servidor.

    Debe coincidir EXACTAMENTE con `kvoice_api.services.manifest_service
    .canonical_bytes`. OJO: usa `ensure_ascii=True` — lo contrario que el
    recibo. Un titulo con acentos se serializa escapado (`\\u00e9`);
    confundir las dos canonicalizaciones es el error mas facil de cometer
    al tocar esto.
    """
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def hash_leaf(raw_commitment: bytes) -> bytes:
    return hashlib.sha256(LEAF_DOMAIN + raw_commitment).digest()


def hash_node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(NODE_DOMAIN + left + right).digest()


def recompute_root(leaf: bytes, steps: list[tuple[str, bytes]]) -> bytes:
    """Reconstruye la raiz desde la hoja.

    `side` indica de que lado esta el hermano: "L" hermano a la izquierda,
    "R" a la derecha. Un arbol de una sola hoja tiene 0 pasos y su raiz es
    la propia hoja (convencion de `merkle.compute_root`).
    """
    accum = leaf
    for side, sibling in steps:
        if side == "L":
            accum = hash_node(sibling, accum)
        elif side == "R":
            accum = hash_node(accum, sibling)
        else:
            raise VerifierError(f"lado invalido en la prueba: {side!r}")
    return accum


def http_get_json(url: str) -> Any:
    req = urllib.request.Request(
        url, headers={"Accept": "application/json", "User-Agent": USER_AGENT}
    )
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")[:300]
        raise VerifierError(f"GET {url} -> HTTP {exc.code}: {body}") from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise VerifierError(f"GET {url} -> sin respuesta: {exc}") from exc


def http_post_json(url: str, payload: dict[str, Any]) -> Any:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
    )
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")[:300]
        raise VerifierError(f"POST {url} -> HTTP {exc.code}: {body}") from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise VerifierError(f"POST {url} -> sin respuesta: {exc}") from exc


# ---------------------------------------------------------------------------
# Carga de entrada
# ---------------------------------------------------------------------------


def load_trust(keys_file: Path) -> dict[str, Any]:
    if not keys_file.exists():
        raise VerifierError(f"no existe el fichero de claves ancladas: {keys_file}")
    try:
        return json.loads(keys_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise VerifierError(f"{keys_file} no es JSON valido: {exc}") from exc


def extract_signed_receipt(doc: dict[str, Any]) -> dict[str, Any]:
    """Acepta el fichero que exporta la app o un `signed_receipt` suelto.

    La app envuelve el recibo en `kvoice_receipt_export`; un auditor puede
    tener solo el objeto interno. Se admiten ambos para no obligar a nadie
    a editar el fichero a mano antes de comprobarlo.
    """
    if "signed_receipt" in doc:
        inner = doc["signed_receipt"]
        if not isinstance(inner, dict):
            raise VerifierError("`signed_receipt` no es un objeto")
        return inner
    if "payload" in doc and "signature_hex" in doc:
        return doc
    raise VerifierError(
        "el fichero no parece un recibo de KVoice: falta `signed_receipt` "
        "(export de la app) o `payload` + `signature_hex`"
    )


def detect_document(doc: dict[str, Any]) -> str:
    """Distingue recibo de manifest sin flags: el formato ya lo dice.

    Pedirle al usuario que declare el tipo seria una oportunidad de
    equivocarse; los dos formatos no comparten campos discriminantes.
    """
    if "signed_receipt" in doc or ("payload" in doc and "signature_hex" in doc):
        return "receipt"
    if (
        "manifest_full" in doc
        or "manifest" in doc
        or doc.get("protocol") == MANIFEST_PROTOCOL
    ):
        return "manifest"
    raise VerifierError(
        "el fichero no parece ni un recibo ni un manifest de KVoice. "
        "Recibo: export de la app o `payload` + `signature_hex`. Manifest: "
        "respuesta de GET /v1/votings/{id}/manifest o su `manifest_full`"
    )


def extract_manifest(
    doc: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any] | None, dict[str, Any]]:
    """Acepta la respuesta de `GET /votings/{id}/manifest` o un
    `manifest_full` suelto.

    Devuelve `(payload, signatures, wrapper_payload, declared)`:
      - `payload`: el contenido firmado y anclado (`manifest_full` SIN el
        bloque `signatures`). Es lo unico de lo que se deriva el hash.
      - `signatures`: bloque de firmas de `manifest_full`.
      - `wrapper_payload`: campo `manifest` del envoltorio, si lo hay,
        para contrastar que no divergen.
      - `declared`: valores que el envoltorio DECLARA (hash, backend del
        anclaje...). Nunca son fuente de verdad, solo material para
        detectar incoherencias.
    """
    wrapper_payload: dict[str, Any] | None = None
    declared: dict[str, Any] = {}
    if "manifest_full" in doc or "manifest" in doc:
        full = doc.get("manifest_full")
        if isinstance(doc.get("manifest"), dict):
            wrapper_payload = doc["manifest"]
        for campo in (
            "manifest_hash_hex",
            "definition_hash_hex",
            "anchor_backend",
            "anchor_tx_id",
            "signature_state",
        ):
            if doc.get(campo) is not None:
                declared[campo] = doc[campo]
        if full is None:
            estado = doc.get("signature_state")
            raise VerifierError(
                "el manifest aun no esta anclado "
                f"(signature_state={estado!r}): no hay `manifest_full` con "
                "las firmas que verificar. Vuelve a exportarlo cuando la "
                "votacion haya reunido todas las firmas"
            )
    else:
        full = doc
    if not isinstance(full, dict) or not isinstance(full.get("signatures"), dict):
        raise VerifierError(
            "`manifest_full` no trae el bloque `signatures`: sin firmas no "
            "hay nada que verificar"
        )
    signatures = full["signatures"]
    payload = {k: v for k, v in full.items() if k != "signatures"}
    return payload, signatures, wrapper_payload, declared


# ---------------------------------------------------------------------------
# Paso 1 — Firma Ed25519 contra la clave anclada en disco
# ---------------------------------------------------------------------------


def check_signature(
    receipt: dict[str, Any], trust: dict[str, Any], report: Report
) -> bool:
    payload = receipt.get("payload")
    if not isinstance(payload, dict):
        return report.add("firma", False, "el recibo no trae `payload`")

    signature_hex = receipt.get("signature_hex")
    if not signature_hex:
        # `signed: false` es un recibo legitimo pero SIN garantia: el
        # servidor lo emite asi cuando no tiene clave de firma disponible.
        return report.add(
            "firma",
            False,
            "recibo SIN firmar (`signature_hex` ausente): no demuestra que "
            "el servidor aceptase el voto",
        )

    typ = payload.get("typ")
    if typ != RECEIPT_TYP:
        return report.add(
            "firma",
            False,
            f"`typ` inesperado: {typ!r} (se esperaba {RECEIPT_TYP!r}). "
            "Separacion de dominio: un acta no puede pasar por recibo",
        )

    for campo in ("voting_id", "commitment_hex", "issued_at"):
        if not payload.get(campo):
            return report.add("firma", False, f"falta el campo obligatorio {campo!r}")

    kid = receipt.get("signer_kid")
    keys = trust.get("keys", {})
    if not kid:
        return report.add("firma", False, "el recibo no indica `signer_kid`")
    if kid not in keys:
        return report.add(
            "firma",
            False,
            f"`kid` {kid!r} desconocido. Claves ancladas: "
            f"{', '.join(sorted(keys)) or 'ninguna'}. Si la clave rotó, "
            "actualiza trusted_keys.json desde una fuente independiente",
        )

    pinned_hex = keys[kid]["public_key_hex"].strip().lower()

    # Si el recibo trae la pubkey, se compara con la anclada. Confiar en la
    # que viene dentro del propio documento seria firmar y sellar el mismo
    # sobre: detectar la discrepancia es justamente el objetivo.
    declared = (receipt.get("signer_pubkey_hex") or "").strip().lower()
    if declared and declared != pinned_hex:
        return report.add(
            "firma",
            False,
            "la pubkey que declara el recibo NO es la anclada localmente.\n"
            f"      declarada: {declared}\n"
            f"      anclada:   {pinned_hex}\n"
            "      Esto es exactamente lo que un operador hostil intentaria.",
            trust="clave anclada en disco",
        )

    try:
        VerifyKey(bytes.fromhex(pinned_hex)).verify(
            canonicalize(payload), bytes.fromhex(signature_hex)
        )
    except BadSignatureError:
        return report.add(
            "firma",
            False,
            "la firma NO corresponde al contenido: el recibo fue alterado o "
            "no lo firmó esa clave",
            trust="clave anclada en disco",
        )
    except ValueError as exc:
        return report.add("firma", False, f"firma o clave mal formadas: {exc}")

    report.facts["voting_id"] = payload["voting_id"]
    report.facts["commitment_hex"] = payload["commitment_hex"]
    report.facts["issued_at"] = payload["issued_at"]
    report.facts["signer_kid"] = kid
    return report.add(
        "firma",
        True,
        f"firma Ed25519 valida con la clave anclada {kid!r}. El servidor "
        f"declaro haber aceptado este voto el {payload['issued_at']}",
        trust="clave anclada en disco (independiente de KVoice)",
    )


# ---------------------------------------------------------------------------
# Paso 2 — Prueba Merkle: se recalcula la raiz desde el commitment
# ---------------------------------------------------------------------------


def check_merkle(
    commitment_hex: str, api_url: str, report: Report
) -> dict[str, Any] | None:
    url = f"{api_url.rstrip('/')}/verify/commitment/{commitment_hex}/proof"
    data = http_get_json(url)

    steps: list[tuple[str, bytes]] = []
    for step in data.get("proof", []):
        side = step.get("side")
        hash_hex = step.get("hash_hex", "")
        try:
            steps.append((side, bytes.fromhex(hash_hex)))
        except ValueError as exc:
            report.add("merkle", False, f"paso de la prueba mal formado: {exc}")
            return None

    try:
        leaf = hash_leaf(bytes.fromhex(commitment_hex))
        computed = recompute_root(leaf, steps)
    except (ValueError, VerifierError) as exc:
        report.add("merkle", False, f"no se pudo recalcular la raiz: {exc}")
        return None

    claimed_hex = (data.get("merkle_root_hex") or "").strip().lower()
    if computed.hex() != claimed_hex:
        report.add(
            "merkle",
            False,
            "la prueba NO reconstruye la raiz que declara la API.\n"
            f"      calculada: {computed.hex()}\n"
            f"      declarada: {claimed_hex}",
            trust="recalculado localmente",
        )
        return None

    report.facts["merkle_root_hex"] = computed.hex()
    report.facts["batch_index"] = data.get("batch_index")
    report.facts["leaf_index"] = data.get("leaf_index")
    report.facts["leaf_count"] = data.get("leaf_count")
    report.facts["external_tx_id"] = data.get("external_tx_id")
    report.facts["external_block"] = data.get("external_block")
    report.facts["anchor_backend"] = data.get("anchor_backend")

    report.add(
        "merkle",
        True,
        f"el commitment esta en la hoja {data.get('leaf_index')} de "
        f"{data.get('leaf_count')} del lote {data.get('batch_index')}, y el "
        f"camino reconstruye la raiz {computed.hex()[:16]}…",
        trust="prueba servida por KVoice pero recalculada aqui",
    )
    return data


# ---------------------------------------------------------------------------
# Pasos 3 y 4 — La cadena, leida de un nodo publico
# ---------------------------------------------------------------------------


def check_onchain(
    proof: dict[str, Any], trust: dict[str, Any], node_url: str, report: Report
) -> None:
    telos = trust.get("telos", {})
    node = node_url.rstrip("/")

    backend = proof.get("anchor_backend")
    if backend != "telos":
        report.add(
            "cadena",
            False,
            f"el lote se anclo con el backend {backend!r}, no en Telos. El "
            "modo 'local' solo produce evidencia HMAC controlada por KVoice: "
            "no es verificable frente al operador",
        )
        return

    batch_index = proof.get("batch_index")
    if batch_index is None:
        report.add("cadena", False, "la prueba no indica `batch_index`")
        return

    # Se comprueba la identidad de la cadena antes de creer sus datos: un
    # nodo de testnet responderia igual de bien y no probaria nada.
    # POST, como hace el backend: es lo estandar en la API de Antelope.
    info = http_post_json(f"{node}/v1/chain/get_info", {})
    chain_id = str(info.get("chain_id", "")).lower()
    expected_chain = telos.get("chain_id", "").lower()
    if expected_chain and chain_id != expected_chain:
        report.add(
            "cadena",
            False,
            f"el nodo {node} dice ser la cadena {chain_id[:16]}…, no la "
            f"esperada {expected_chain[:16]}…",
        )
        return

    contract = telos.get("anchor_contract")
    rows = http_post_json(
        f"{node}/v1/chain/get_table_rows",
        {
            "code": contract,
            "scope": contract,
            "table": telos.get("anchors_table", "anchors"),
            "index_position": 2,  # indice secundario `bybatch`
            "key_type": "i64",
            "lower_bound": str(batch_index),
            "upper_bound": str(batch_index),
            "limit": 50,
            "json": True,
        },
    ).get("rows", [])

    if not rows:
        report.add(
            "cadena",
            False,
            f"el lote {batch_index} NO aparece en la tabla `anchors` de "
            f"{contract}. O no se ha anclado todavia, o no existe",
        )
        return

    expected_root = report.facts.get("merkle_root_hex", "")
    matching = [
        r for r in rows if str(r.get("merkle_root", "")).lower() == expected_root
    ]
    if not matching:
        onchain_roots = ", ".join(
            str(r.get("merkle_root", ""))[:16] + "…" for r in rows
        )
        report.add(
            "cadena",
            False,
            "la raiz que reconstruye tu recibo NO esta en la cadena para ese "
            f"lote.\n      tu recibo: {expected_root[:16]}…\n"
            f"      en cadena: {onchain_roots}",
            trust="nodo publico de Telos",
        )
        return

    row = matching[0]
    report.facts["onchain_anchored_at"] = row.get("anchored_at")
    report.facts["onchain_leaf_count"] = row.get("leaf_count")

    report.add(
        "cadena",
        True,
        f"la raiz esta registrada en Telos en la cuenta {contract}, lote "
        f"{batch_index}, sellada el {row.get('anchored_at')}",
        trust=f"nodo publico {node} (independiente de KVoice)",
    )

    # Discrepancia de leaf_count: la cadena manda. Si no cuadra, el lote de
    # la BD no es el que se anclo.
    api_leaves = proof.get("leaf_count")
    chain_leaves = row.get("leaf_count")
    if api_leaves is not None and chain_leaves is not None:
        if int(api_leaves) != int(chain_leaves):
            report.add(
                "coherencia",
                False,
                f"la API dice {api_leaves} hojas y la cadena {chain_leaves}. "
                "El lote no es el mismo",
                trust="nodo publico de Telos",
            )

    # Irreversibilidad: estar en un bloque no basta si ese bloque aun puede
    # revertirse en un fork.
    block = proof.get("external_block")
    if block is None:
        report.add(
            "irreversibilidad",
            False,
            "la API no indica el bloque del anclaje: no se puede comprobar",
        )
        return

    lib = int(info.get("last_irreversible_block_num", 0))
    if int(block) <= lib:
        report.add(
            "irreversibilidad",
            True,
            f"bloque {block} <= ultimo irreversible {lib}: el anclaje ya no "
            "puede revertirse",
            trust="nodo publico de Telos",
        )
    else:
        report.add(
            "irreversibilidad",
            False,
            f"bloque {block} > ultimo irreversible {lib}: anclado pero aun "
            f"reversible (faltan ~{int(block) - lib} bloques). Vuelve a "
            "comprobarlo en unos segundos",
            trust="nodo publico de Telos",
        )


# ---------------------------------------------------------------------------
# Manifest — Paso 1: el hash se recalcula del contenido, nunca se cree
# ---------------------------------------------------------------------------


def check_manifest_hash(
    payload: dict[str, Any],
    wrapper_payload: dict[str, Any] | None,
    declared: dict[str, Any],
    report: Report,
) -> bytes | None:
    """Recalcula `sha256(canonical_ascii(payload))` y contrasta lo declarado.

    El hash NUNCA se toma del documento: todas las firmas y el anclaje se
    verifican contra el hash recalculado aqui. Si se usara el declarado,
    un atacante podria pegar el hash de otro documento legitimo (un acta,
    otro manifest) junto a sus firmas reales y todo "verificaria".
    """
    protocol = payload.get("protocol")
    if protocol != MANIFEST_PROTOCOL:
        report.add(
            "hash",
            False,
            f"`protocol` inesperado: {protocol!r} (se esperaba "
            f"{MANIFEST_PROTOCOL!r})",
        )
        return None
    definition = payload.get("definition")
    if not isinstance(definition, dict):
        report.add("hash", False, "el manifest no trae `definition`")
        return None

    computed = hashlib.sha256(canonicalize_ascii(payload)).digest()
    report.facts["manifest_hash_hex"] = computed.hex()
    report.facts["voting_id"] = definition.get("voting_id")
    report.facts["title"] = definition.get("title")
    census = payload.get("census") or {}
    report.facts["eligible_count"] = census.get("eligible_count")

    if wrapper_payload is not None and wrapper_payload != payload:
        report.add(
            "coherencia",
            False,
            "el campo `manifest` del envoltorio NO coincide con el contenido "
            "de `manifest_full`: alguien edito uno de los dos",
        )

    declared_hash = (declared.get("manifest_hash_hex") or "").strip().lower()
    if declared_hash and declared_hash != computed.hex():
        report.add(
            "hash",
            False,
            "el hash declarado NO es el del contenido.\n"
            f"      declarado: {declared_hash}\n"
            f"      calculado: {computed.hex()}\n"
            "      O el contenido fue alterado, o el envoltorio miente",
            trust="recalculado localmente",
        )
    else:
        report.add(
            "hash",
            True,
            f"hash del manifest recalculado: {computed.hex()[:16]}… "
            "(las firmas y la cadena se comprueban contra ESTE valor)",
            trust="recalculado localmente",
        )

    declared_def = (declared.get("definition_hash_hex") or "").strip().lower()
    if declared_def:
        def_hash = hashlib.sha256(canonicalize_ascii(definition)).hexdigest()
        if def_hash != declared_def:
            report.add(
                "definicion",
                False,
                "el `definition_hash` declarado no corresponde a la "
                "definicion incluida.\n"
                f"      declarado: {declared_def}\n"
                f"      calculado: {def_hash}",
                trust="recalculado localmente",
            )
        else:
            report.add(
                "definicion",
                True,
                "el hash de la definicion (el que se re-verifica en cada "
                "voto) corresponde a la definicion incluida",
                trust="recalculado localmente",
            )
    return computed


# ---------------------------------------------------------------------------
# Manifest — Paso 2: las firmas. Cubren los 32 bytes del hash, NO el JSON
# ---------------------------------------------------------------------------


def _verify_over_hash(
    pubkey_hex: str, signature_hex: str, m_hash: bytes
) -> str | None:
    """None si la firma Ed25519 sobre los bytes del hash verifica; si no,
    el motivo. Las firmas del manifest cubren el HASH (32 bytes), no el
    JSON canonico — diferencia clave con el recibo (manifest_service:
    `signer.sign(m_hash_bytes)`)."""
    try:
        VerifyKey(bytes.fromhex(pubkey_hex)).verify(
            m_hash, bytes.fromhex(signature_hex)
        )
        return None
    except BadSignatureError:
        return "la firma NO corresponde al hash del manifest"
    except (ValueError, TypeError) as exc:
        return f"firma o clave mal formadas: {exc}"


def check_manifest_signatures(
    m_hash: bytes,
    payload: dict[str, Any],
    signatures: dict[str, Any],
    trust: dict[str, Any],
    report: Report,
) -> bool:
    """Verifica las N+2 firmas con tres niveles de confianza distintos.

    - Servidor: contra la clave ANCLADA EN DISCO (trusted_keys.json), como
      los recibos. La que declare el documento solo sirve para detectar la
      discrepancia.
    - Custodios: contra las pubkeys publicadas DENTRO del payload
      (`crypto.custodians[*].ed25519_pubkey_hex`), cubiertas por el hash
      anclado: sustituir una clave cambia el hash y el paso de cadena
      falla. Se exige el umbral n completo y claves distintas.
    - Organizador: su pubkey NO esta en el payload; se verifica con la que
      declara el propio bloque de firmas y se dice claramente que eso solo
      demuestra consistencia interna, no identidad.
    """
    ok = True

    # --- Servidor ---------------------------------------------------------
    server = signatures.get("server")
    if not isinstance(server, dict):
        ok = report.add("firma servidor", False, "falta la firma del servidor")
    else:
        kid = server.get("signer_kid")
        keys = trust.get("keys", {})
        if not kid:
            ok = report.add(
                "firma servidor",
                False,
                "la firma del servidor no indica `signer_kid`",
            )
        elif kid not in keys:
            ok = report.add(
                "firma servidor",
                False,
                f"`kid` {kid!r} desconocido. Claves ancladas: "
                f"{', '.join(sorted(keys)) or 'ninguna'}. Si la clave rotó, "
                "actualiza trusted_keys.json desde una fuente independiente",
            )
        else:
            pinned_hex = keys[kid]["public_key_hex"].strip().lower()
            declared_pk = (server.get("pubkey_hex") or "").strip().lower()
            if declared_pk and declared_pk != pinned_hex:
                ok = report.add(
                    "firma servidor",
                    False,
                    "la pubkey que declara el manifest NO es la anclada "
                    "localmente.\n"
                    f"      declarada: {declared_pk}\n"
                    f"      anclada:   {pinned_hex}",
                    trust="clave anclada en disco",
                )
            else:
                error = _verify_over_hash(
                    pinned_hex, server.get("signature_hex") or "", m_hash
                )
                if error:
                    ok = report.add(
                        "firma servidor",
                        False,
                        error,
                        trust="clave anclada en disco",
                    )
                else:
                    report.facts["signer_kid"] = kid
                    report.add(
                        "firma servidor",
                        True,
                        f"firma Ed25519 valida con la clave anclada {kid!r}",
                        trust="clave anclada en disco (independiente de KVoice)",
                    )

    crypto = payload.get("crypto")

    # --- Organizador --------------------------------------------------------
    organizer = signatures.get("organizer")
    if not isinstance(organizer, dict):
        if crypto:
            ok = report.add(
                "firma organizador",
                False,
                "votacion con custodios SIN firma del organizador: el "
                "backend no ancla un manifest asi (falta una de las N+2)",
            )
        else:
            report.add(
                "firma organizador",
                True,
                "ausente: regimen server-only de votaciones sin custodios "
                "(deuda documentada en el backend, no un fallo del documento)",
            )
    else:
        declared_pk = (organizer.get("pubkey_hex") or "").strip().lower()
        error = _verify_over_hash(
            declared_pk, organizer.get("signature_hex") or "", m_hash
        )
        if error:
            ok = report.add("firma organizador", False, error)
        else:
            report.add(
                "firma organizador",
                True,
                "firma valida con la clave que declara el documento. OJO: esa "
                "clave NO esta dentro del contenido anclado; identifica al "
                "organizador solo si la conoces por otra via",
                trust="clave declarada en el propio documento (NO anclada)",
            )

    # --- Custodios ------------------------------------------------------
    entries = signatures.get("custodians") or []
    if not crypto:
        if entries:
            ok = report.add(
                "firmas custodios",
                False,
                "el manifest no declara custodios en `crypto` pero trae "
                f"{len(entries)} firma(s) de custodio: incoherente",
            )
        return ok

    threshold_n = int(crypto.get("threshold_n") or 0)
    threshold_k = int(crypto.get("threshold_k") or 0)
    report.facts["threshold"] = f"{threshold_k}-de-{threshold_n}"
    anchored_keys: dict[str, Any] = {}
    for c in crypto.get("custodians") or []:
        pk = (c.get("ed25519_pubkey_hex") or "").strip().lower()
        if pk:
            anchored_keys[pk] = c.get("holder_index")

    valid_holders: set[Any] = set()
    problemas: list[str] = []
    for i, entry in enumerate(entries, start=1):
        pk = (entry.get("pubkey_hex") or "").strip().lower()
        if pk not in anchored_keys:
            problemas.append(
                f"firma #{i}: la clave {pk[:16] or '?'}… NO es ninguna de "
                "las ancladas en `crypto.custodians`"
            )
            continue
        holder = anchored_keys[pk]
        if holder in valid_holders:
            problemas.append(f"custodio {holder}: firma duplicada")
            continue
        error = _verify_over_hash(pk, entry.get("signature_hex") or "", m_hash)
        if error:
            problemas.append(f"custodio {holder}: {error}")
        else:
            valid_holders.add(holder)

    if problemas or len(valid_holders) < threshold_n:
        detalle = f"validas {len(valid_holders)} de {threshold_n} exigidas" + (
            ":\n      " + "\n      ".join(problemas) if problemas else ""
        )
        ok = report.add(
            "firmas custodios",
            False,
            detalle,
            trust="claves dentro del contenido anclado",
        )
    else:
        report.add(
            "firmas custodios",
            True,
            f"los {threshold_n} custodios firmaron el hash, cada uno con su "
            "clave publicada dentro del propio contenido anclado",
            trust="claves dentro del contenido anclado (cubiertas por el hash)",
        )
    return ok


# ---------------------------------------------------------------------------
# Manifest — Pasos 3 y 4: la cadena. batch 0 esta reservado a manifests
# ---------------------------------------------------------------------------


def _parse_chain_time(value: Any) -> datetime:
    """Tiempos de Antelope: ISO-8601 UTC sin sufijo de zona
    (`2026-08-02T17:23:04`, con o sin milisegundos)."""
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def fetch_manifest_anchor_rows(
    node: str, telos: dict[str, Any]
) -> list[dict[str, Any]]:
    """Todas las filas con `batch_index = 0` de la tabla `anchors`.

    Primero por el indice secundario `bybatch` (una peticion). Si hubiera
    mas de 1000 manifests, ese indice no pagina bien entre claves iguales
    (`next_key` devolveria otra vez 0), asi que se cae a un escaneo por
    clave primaria, que si es paginable de forma fiable.
    """
    contract = telos.get("anchor_contract")
    table = telos.get("anchors_table", "anchors")
    url = f"{node}/v1/chain/get_table_rows"
    base = {"code": contract, "scope": contract, "table": table, "json": True}
    resp = http_post_json(
        url,
        {
            **base,
            "index_position": 2,
            "key_type": "i64",
            "lower_bound": str(MANIFEST_BATCH_INDEX),
            "upper_bound": str(MANIFEST_BATCH_INDEX),
            "limit": 1000,
        },
    )
    if not resp.get("more"):
        return list(resp.get("rows", []))

    rows: list[dict[str, Any]] = []
    lower = "0"
    for _ in range(50):
        resp = http_post_json(
            url,
            {**base, "index_position": 1, "key_type": "i64",
             "lower_bound": lower, "limit": 1000},
        )
        for r in resp.get("rows", []):
            if int(r.get("batch_index", -1)) == MANIFEST_BATCH_INDEX:
                rows.append(r)
        if not resp.get("more"):
            return rows
        lower = str(resp.get("next_key"))
    raise VerifierError(
        "la tabla `anchors` es demasiado grande para escanearla entera "
        "(>50 paginas); habria que ampliar el verificador"
    )


def check_manifest_onchain(
    m_hash_hex: str,
    declared: dict[str, Any],
    trust: dict[str, Any],
    node_url: str,
    report: Report,
) -> None:
    """El hash recalculado debe estar en la tabla `anchors` (batch 0) y en
    un bloque ya irreversible.

    A diferencia del recibo, aqui no hay `external_block` que consultar:
    el envoltorio del manifest no lo publica. Se usa el sello temporal
    on-chain de la fila (`anchored_at`, que es el timestamp del bloque que
    ejecuto la transaccion) contra el timestamp del ultimo bloque
    irreversible. Si `anchored_at <= t(LIB)`, el bloque del anclaje es
    anterior o igual al LIB y ya no puede revertirse.
    """
    telos = trust.get("telos", {})
    node = node_url.rstrip("/")

    backend = declared.get("anchor_backend")
    if backend is not None and backend != "telos":
        report.add(
            "cadena",
            False,
            f"el manifest se anclo con el backend {backend!r}, no en Telos. "
            "El modo 'local' solo produce evidencia HMAC controlada por "
            "KVoice: no es verificable frente al operador",
        )
        return

    info = http_post_json(f"{node}/v1/chain/get_info", {})
    chain_id = str(info.get("chain_id", "")).lower()
    expected_chain = telos.get("chain_id", "").lower()
    if expected_chain and chain_id != expected_chain:
        report.add(
            "cadena",
            False,
            f"el nodo {node} dice ser la cadena {chain_id[:16]}…, no la "
            f"esperada {expected_chain[:16]}…",
        )
        return

    contract = telos.get("anchor_contract")
    rows = fetch_manifest_anchor_rows(node, telos)
    matching = [
        r for r in rows if str(r.get("merkle_root", "")).lower() == m_hash_hex
    ]
    if not matching:
        report.add(
            "cadena",
            False,
            f"el hash del manifest NO esta en la tabla `anchors` de "
            f"{contract} (batch 0, {len(rows)} manifests anclados). O no se "
            "ha anclado todavia, o el contenido no es el que se anclo",
            trust="nodo publico de Telos",
        )
        return

    row = matching[0]
    report.facts["onchain_row_id"] = row.get("id")
    report.facts["onchain_anchored_at"] = row.get("anchored_at")
    report.add(
        "cadena",
        True,
        f"el hash esta registrado en Telos en la cuenta {contract} "
        f"(fila {row.get('id')} de `anchors`), sellado el "
        f"{row.get('anchored_at')}",
        trust=f"nodo publico {node} (independiente de KVoice)",
    )

    # Un manifest se ancla como lote de 1 hoja (manifest_service).
    chain_leaves = row.get("leaf_count")
    if chain_leaves is not None and int(chain_leaves) != 1:
        report.add(
            "coherencia",
            False,
            f"la fila anclada declara {chain_leaves} hojas; un manifest "
            "siempre se ancla con leaf_count = 1",
            trust="nodo publico de Telos",
        )

    lib = int(info.get("last_irreversible_block_num", 0))
    lib_block = http_post_json(
        f"{node}/v1/chain/get_block", {"block_num_or_id": lib}
    )
    try:
        lib_time = _parse_chain_time(lib_block.get("timestamp"))
        row_time = _parse_chain_time(row.get("anchored_at"))
    except (ValueError, TypeError) as exc:
        report.add(
            "irreversibilidad",
            False,
            f"no se pudo interpretar el sello temporal: {exc}",
        )
        return

    if row_time <= lib_time:
        report.add(
            "irreversibilidad",
            True,
            f"anclado el {row.get('anchored_at')} <= ultimo bloque "
            f"irreversible ({lib_block.get('timestamp')}): el anclaje ya no "
            "puede revertirse",
            trust="nodo publico de Telos",
        )
    else:
        faltan = int((row_time - lib_time).total_seconds())
        report.add(
            "irreversibilidad",
            False,
            f"anclado el {row.get('anchored_at')}, posterior al ultimo "
            f"bloque irreversible ({lib_block.get('timestamp')}): anclado "
            f"pero aun reversible (~{faltan} s). Vuelve a comprobarlo en "
            "unos segundos",
            trust="nodo publico de Telos",
        )


# ---------------------------------------------------------------------------
# Presentacion
# ---------------------------------------------------------------------------


def print_human(report: Report, offline: bool, kind: str = "receipt") -> None:
    titulo = "recibos" if kind == "receipt" else "manifests"
    print()
    print("=" * 66)
    print(f"  Verificador independiente de {titulo} KVoice")
    print("=" * 66)

    for check in report.checks:
        marca = "OK  " if check.passed else "FALLA"
        print(f"\n[{marca}] {check.name.upper()}")
        for linea in check.detail.split("\n"):
            print(f"      {linea}")
        if check.trust:
            print(f"      fuente de confianza: {check.trust}")

    print()
    print("-" * 66)
    if report.ok:
        print("  RESULTADO: todas las comprobaciones pasan.")
    else:
        fallidas = [c.name for c in report.checks if not c.passed]
        print(f"  RESULTADO: FALLA -> {', '.join(fallidas)}")
    print("-" * 66)

    # El alcance se redacta segun lo que REALMENTE se comprobo. En offline
    # no se ha visto ni el arbol ni la cadena, y afirmar inclusion ahi seria
    # justo el tipo de exageracion que este programa existe para evitar.
    if kind == "manifest":
        if offline:
            print(
                "\n  Modo offline: solo se comprobaron el HASH y las FIRMAS. NO se ha\n"
                "  comprobado que ese hash este anclado en la cadena: sin ese paso,\n"
                "  nada impide que exista otro manifest distinto tambien firmado.\n"
                "  Ejecutalo sin --offline para eso."
            )
        else:
            print(
                "\n  Alcance: esto demuestra que la definicion de la votacion (preguntas,\n"
                "  censo declarado, custodios y umbral) quedo fijada, firmada y anclada,\n"
                "  y que nadie la ha alterado despues. NO demuestra quien es cada\n"
                "  custodio en el mundo real, ni que el censo declarado fuese legitimo,\n"
                "  ni nada sobre los votos emitidos despues."
            )
    elif offline:
        print(
            "\n  Modo offline: solo se comprobo la FIRMA. Esto demuestra que el\n"
            "  servidor emitio ese recibo y que no ha sido alterado. NO se ha\n"
            "  comprobado que el voto siga incluido en ningun lote, ni que haya\n"
            "  nada anclado en la cadena. Ejecutalo sin --offline para eso."
        )
    else:
        print(
            "\n  Alcance: esto demuestra que TU recibo fue aceptado y quedo\n"
            "  incluido en un lote anclado. NO demuestra que el censo fuese\n"
            "  legitimo, ni que se contaran todos los votos, ni que el recuento\n"
            "  corresponda a los votos cifrados."
        )
    print()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Verifica un recibo de voto o un manifest electoral de KVoice "
            "sin confiar en KVoice. El tipo de documento se detecta solo."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "documento",
        type=Path,
        help=(
            "fichero JSON: recibo exportado por la app o respuesta de "
            "GET /v1/votings/{id}/manifest"
        ),
    )
    parser.add_argument(
        "--api-url",
        default=DEFAULT_API_URL,
        help=f"API de KVoice para la prueba Merkle (por defecto {DEFAULT_API_URL})",
    )
    parser.add_argument(
        "--telos-node",
        default=DEFAULT_TELOS_NODE,
        help=(
            "nodo Telos para leer la cadena. Usa uno que no controle KVoice; "
            f"por defecto {DEFAULT_TELOS_NODE}"
        ),
    )
    parser.add_argument(
        "--keys",
        type=Path,
        default=DEFAULT_KEYS_FILE,
        help="fichero de claves publicas ancladas (raiz de confianza)",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="comprueba solo firma(s) y hash, sin ninguna peticion de red",
    )
    parser.add_argument("--json", action="store_true", help="salida JSON")
    args = parser.parse_args(argv)

    report = Report()
    kind = "receipt"
    try:
        trust = load_trust(args.keys)
        if not args.documento.exists():
            raise VerifierError(f"no existe el fichero {args.documento}")
        doc = json.loads(args.documento.read_text(encoding="utf-8"))
        kind = detect_document(doc)
        report.facts["document_type"] = kind

        if kind == "receipt":
            receipt = extract_signed_receipt(doc)
            firma_ok = check_signature(receipt, trust, report)
            if not args.offline and firma_ok:
                proof = check_merkle(
                    report.facts["commitment_hex"], args.api_url, report
                )
                if proof is not None:
                    check_onchain(proof, trust, args.telos_node, report)
        else:
            payload, signatures, wrapper_payload, declared = extract_manifest(doc)
            m_hash = check_manifest_hash(
                payload, wrapper_payload, declared, report
            )
            if m_hash is not None:
                check_manifest_signatures(
                    m_hash, payload, signatures, trust, report
                )
                # La cadena se consulta aunque alguna firma falle: el hash
                # es la identidad del contenido, y saber si ESE contenido
                # esta anclado es informacion util para el informe (p. ej.
                # contenido legitimo con una firma manipulada, o contenido
                # alterado que ademas no esta en la cadena).
                if not args.offline:
                    check_manifest_onchain(
                        m_hash.hex(), declared, trust, args.telos_node, report
                    )

    except json.JSONDecodeError as exc:
        sys.stderr.write(f"El fichero no es JSON valido: {exc}\n")
        return 2
    except VerifierError as exc:
        sys.stderr.write(f"Error: {exc}\n")
        return 2

    if args.json:
        print(
            json.dumps(
                {
                    "ok": report.ok,
                    "checks": [
                        {
                            "name": c.name,
                            "passed": c.passed,
                            "detail": c.detail,
                            "trust": c.trust,
                        }
                        for c in report.checks
                    ],
                    "facts": report.facts,
                },
                indent=2,
                ensure_ascii=False,
            )
        )
    else:
        print_human(report, args.offline, kind)

    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
