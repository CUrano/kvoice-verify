#!/usr/bin/env python3
"""Verificador independiente de recibos de voto de KVoice (P1-01).

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

USO
===

    python kvoice_verify.py recibo.json
    python kvoice_verify.py recibo.json --offline      # solo la firma
    python kvoice_verify.py recibo.json --json         # salida automatizable

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
# Presentacion
# ---------------------------------------------------------------------------


def print_human(report: Report, offline: bool) -> None:
    print()
    print("=" * 66)
    print("  Verificador independiente de recibos KVoice")
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
    if offline:
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
        description="Verifica un recibo de voto de KVoice sin confiar en KVoice.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("recibo", type=Path, help="fichero JSON exportado por la app")
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
        help="comprueba solo la firma, sin ninguna peticion de red",
    )
    parser.add_argument("--json", action="store_true", help="salida JSON")
    args = parser.parse_args(argv)

    report = Report()
    try:
        trust = load_trust(args.keys)
        if not args.recibo.exists():
            raise VerifierError(f"no existe el fichero {args.recibo}")
        doc = json.loads(args.recibo.read_text(encoding="utf-8"))
        receipt = extract_signed_receipt(doc)

        firma_ok = check_signature(receipt, trust, report)

        if not args.offline and firma_ok:
            proof = check_merkle(
                report.facts["commitment_hex"], args.api_url, report
            )
            if proof is not None:
                check_onchain(proof, trust, args.telos_node, report)

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
        print_human(report, args.offline)

    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
