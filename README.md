# kvoice-verify — Verificador independiente de KVoice

Comprueba que un recibo de voto es auténtico y que quedó incluido en un
lote anclado en Telos — **sin tener que fiarte de KVoice**.

Este repositorio se publica separado del sistema a propósito: un
verificador que se descarga del mismo sitio que el software verificado
pierde parte de su valor. Licencia MIT.

## Por qué existe

KVoice firma un recibo por cada voto, agrupa los commitments en un árbol
Merkle y ancla la raíz en la cadena. Hasta ahora, la única forma de
comprobar todo eso era **preguntarle a KVoice**: el fichero que exporta la
app dice literalmente «haz POST a `/v1/verify/receipt`».

Eso es circular. Si el operador miente, también miente el endpoint con el
que lo compruebas. Este programa rompe el círculo.

## Qué comprueba, y de quién se fía en cada paso

| Paso | Qué verifica | Fuente de verdad | ¿Puede KVoice mentir? |
|------|--------------|------------------|------------------------|
| 1. Firma | Ed25519 sobre el JSON canónico | `trusted_keys.json`, en tu disco | **No** |
| 2. Merkle | La raíz se reconstruye desde tu commitment | recalculado aquí | **No** (*) |
| 3. Cadena | La raíz está en la tabla `anchors` | nodo público de Telos | **No** |
| 4. Irreversible | El bloque ya no puede revertirse | nodo público de Telos | **No** |

(*) La prueba la sirve KVoice, pero es autoverificable: si la manipula, la
raíz que sale no coincide con la que está en la cadena.

**La pieza clave es `trusted_keys.json`.** El verificador usa la clave de
ese fichero, **nunca** la que viene dentro del recibo ni la que sirve la
API. Si no coinciden, falla y te dice por qué. Contrasta esa clave con la
que publica el operador (`docs/ACTA_PUBLIC_KEYS.md` en el repositorio de
KVoice) y, mejor, con una fuente que KVoice no controle.

## Qué NO demuestra

Conviene ser exacto, porque es fácil vender esto de más:

- **No** demuestra que el censo fuese legítimo.
- **No** demuestra que se contaran *todos* los votos. Prueba que **tu**
  recibo está incluido, no que el conjunto esté completo.
- **No** demuestra que el recuento corresponda a los votos cifrados. Eso
  exige recuento homomórfico con pruebas Chaum-Pedersen, que todavía no
  existe (ver la revisión criptográfica en el repositorio de KVoice).

Es decir: **verificabilidad individual, no universal.**

## Uso

```bash
pip install -r requirements.txt

python kvoice_verify.py recibo.json
python kvoice_verify.py recibo.json --offline    # solo la firma, sin red
python kvoice_verify.py recibo.json --json       # para automatizar
```

`recibo.json` es el fichero que descarga la app desde el detalle de la
votación. También acepta un objeto `signed_receipt` suelto.

Opciones útiles:

```bash
--telos-node https://otro-nodo.telos.net   # usa un nodo que no controlemos
--keys mis_claves.json                     # tu propia raíz de confianza
--api-url https://api.kvoice.org.es/v1     # otra instancia
```

Códigos de salida: `0` todo correcto, `1` alguna comprobación falla,
`2` error de uso o de red.

> **Usa un nodo Telos que no controle KVoice.** El valor por defecto
> (`mainnet.telos.net`) es un nodo público de terceros, pero si vas a
> apoyar una reclamación en esto, elige tú el nodo. Es una línea de
> comando y elimina una suposición.

## Estado actual

La API pública es **`https://api.kvoice.org.es/v1`** (publicada el
12/08/2026 vía túnel Cloudflare; si el DNS aún no resuelve para ti, la
delegación de nameservers sigue propagando). El paso 1 (la firma)
funciona siempre sin red, con `--offline`.

## Diseño

- **Un solo fichero** (`kvoice_verify.py`) y **una sola dependencia**
  (PyNaCl, para Ed25519). Un verificador con veinte dependencias es un
  verificador que nadie audita. HTTP, JSON y SHA-256 salen de la librería
  estándar.
- **Sin estado, sin configuración oculta.** Todo lo que determina el
  resultado está en el fichero de claves o en la línea de comandos.
- **Pensado para extraerse a su propio repositorio.** No importa nada de
  `kvoice_api`: reimplementa la canonicalización y el árbol Merkle a
  propósito, para que un fallo del backend no se propague al verificador.

### Detalles que hay que replicar exactamente

Si cambias el backend, esto tiene que cambiar a la vez o nada verificará:

- **JSON canónico**: `sort_keys=True`, separadores `(",", ":")`,
  `ensure_ascii=False`, UTF-8.
- **Hoja Merkle**: `SHA256(0x00 || commitment)`.
- **Nodo interno**: `SHA256(0x01 || izq || der)`. Los prefijos distintos
  evitan que un nodo interno se haga pasar por hoja.
- **Nivel impar**: se duplica el último nodo (convención Bitcoin).
- **Recibo**: la firma cubre el **JSON canónico directamente**.
- **Acta**: la firma cubre el **SHA-256** del JSON canónico. *No es lo
  mismo que el recibo*, y confundirlos es el error más fácil de cometer.

Los tests replican el algoritmo del backend y comparan resultados, así que
una divergencia sale como fallo en vez de como misterio.

## Tests

```bash
pip install pytest
python -m pytest tests/ -q
```

47 tests. Además de los casos válidos, cubren el rechazo de: payload
alterado, firma con un bit cambiado, firma de otra clave, pubkey declarada
distinta de la anclada, `kid` desconocido, recibo sin firmar, `typ` de otro
dominio, campo inyectado en el payload, raíz que no cuadra, hermano Merkle
manipulado, lados L/R invertidos, prueba de otro commitment, nodo de otra
cadena, raíz distinta en la cadena, lote ausente, backend `local`,
`leaf_count` incoherente y anclaje aún reversible.

Un verificador solo probado con entradas válidas no sirve: lo único que
importa es que diga **no** cuando toca.
