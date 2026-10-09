# evidence-pack-py

Crea y verifica carpetas locales de evidencia con manifiestos SHA-256 e índice de hallazgos. Python 3.12+, sin dependencias de ejecución.

[English](docs/README.en.md) · [Perfil y límites](docs/perfil.md) · [Cambios](CHANGELOG.md)

## Para qué sirve

Un hallazgo puede depender de varios archivos y un mismo archivo puede respaldar varios hallazgos. Esta biblioteca conserva esa relación, copia el contenido a un directorio nuevo y permite detectar diferencias respecto de los manifiestos guardados.

La verificación comprueba integridad relativa a esos manifiestos. No acredita autoría, veracidad, procedencia, fecha cierta, cadena de custodia ni validez jurídica. Si alguien reemplaza contenido y manifiestos de forma coherente, la verificación puede aprobar. No añade firmas ni un protocolo criptográfico propio.

## Inicio rápido

Desde un checkout, en un entorno virtual de Python 3.12 o posterior:

```sh
python -m pip install -e .
evidence-pack create examples/payload example-pack --findings examples/findings.json
evidence-pack verify example-pack
```

También puede usarse `python -m evidence_pack` en lugar de `evidence-pack`. El directorio padre del destino debe existir; `example-pack` no debe existir. Para repetir el ejemplo, elige otro destino nuevo.

El archivo de entrada `examples/findings.json` contiene rutas relativas al origen:

```json
{
  "OBS-001": ["observacion.txt"]
}
```

Se copian **todos los archivos regulares** del origen, incluidos los ocultos y los que no aparecen en el índice. Revisa la carpeta antes de compartir el paquete. Los directorios vacíos no se conservan; usa un archivo marcador si necesitas representarlos. No se preservan permisos, propietarios, tiempos, ACL, atributos extendidos ni metadatos alternativos del sistema de archivos.

## Resultado

```text
example-pack/
├── bagit.txt
├── manifest-sha256.txt
├── tagmanifest-sha256.txt
├── index.json
└── data/
    └── observacion.txt
```

El manifiesto principal cubre los archivos de `data/`. El manifiesto de etiquetas cubre `bagit.txt`, el manifiesto principal e `index.json`. El índice almacenado usa rutas relativas al paquete:

```json
{
  "findings": {"OBS-001": ["data/observacion.txt"]},
  "profile": "evidence-pack/1"
}
```

Las salidas de CLI son JSON. Para un árbol estable, el orden de los resultados y los bytes generados son deterministas; no se insertan marcas de tiempo ni rutas absolutas. Los textos de errores de E/S dependen del sistema operativo.

- Código `0`: creación terminada y verificada, o paquete válido para este perfil.
- Código `1`: `verify` detectó problemas, incluidos errores de lectura.
- Código `2`: error de entrada o de creación; los errores de argumentos de CLI usan stderr y no son JSON.

## API

```python
from evidence_pack import create_pack, verify_pack

created = create_pack(
    "documentos",
    "entrega-001",
    {"OBS-001": ["acta.txt", "anexos/captura.png"]},
)
assert created.valid

report = verify_pack("entrega-001")
for issue in report.issues:
    print(issue.code, issue.path, issue.message)
print(report.to_dict())
```

`VerificationReport` es inmutable e incluye `valid`, `payload_files`, `payload_bytes`, `findings`, `referenced_files` e `issues`. Los conteos reflejan lo inspeccionado; pueden ser parciales cuando un error estructural impide continuar. `valid` significa únicamente que pasó este perfil.

`verify_pack` devuelve un informe para errores esperados de formato y E/S. `create_pack` y `load_findings` usan excepciones derivadas de `EvidencePackError`:

- `InputError`: entrada inválida, formato no admitido, cambio detectado o fallo de lectura.
- `DestinationExistsError`: el destino ya existe y no se modificó.
- `CreationIncompleteError`: el destino nuevo fue reservado, pero la creación no terminó. Su causa conserva el error original.

Cada excepción expone `issue` con `code`, `path` y `message`. Los IDs admiten letras ASCII, números, punto, guion y guion bajo; comienzan por letra o número y tienen un máximo de 64 caracteres. Se requiere al menos un hallazgo y una ruta válida por hallazgo. Se permiten archivos compartidos entre hallazgos y archivos de contexto no referenciados.

## Política de archivos

- Solo carpetas locales estables y archivos regulares. No se siguen enlaces simbólicos ni puntos de reanálisis; también se rechazan hard links y archivos especiales.
- No hay descarga, extracción de archivos comprimidos ni ejecución de contenido.
- Rutas de índice relativas, separadas por `/`, ya normalizadas a NFC. Se rechazan rutas absolutas, `..`, componentes vacíos, separadores alternativos, controles, `%`, nombres reservados y colisiones por casefold. La política es deliberadamente más estricta que los nombres que algunos sistemas permiten.
- Origen y destino no pueden solaparse. No se acepta un destino existente, aunque esté vacío.
- El destino se reserva mediante `mkdir` exclusivo. La declaración `bagit.txt` se escribe al final y después se verifica el paquete. La creación **no es una publicación atómica**, una transacción ni una garantía de durabilidad ante caída del sistema.
- Si una operación falla, no se borra automáticamente el directorio parcial. Revísalo manualmente y usa otro destino para reintentar. Un corte o interrupción puede dejar una carpeta incompleta sin informe final.
- No es un aislamiento frente a un proceso que modifica activamente las rutas. Trabaja en carpetas privadas sin escritores concurrentes. La detección de cambios ordinarios por inventario y metadatos no equivale a una instantánea consistente.

Implementación portable para Windows, macOS y Linux. Las pruebas registradas de esta entrega se ejecutaron en Linux con Python 3.12; los otros sistemas requieren validación propia. En macOS, evita alias de carpetas como `/var` si son enlaces: usa la ruta física. Los detalles y límites de tamaño se encuentran en [el perfil](docs/perfil.md).

## BagIt e interoperabilidad

La estructura sigue un perfil restringido de [BagIt 1.0, RFC 8493](https://www.rfc-editor.org/rfc/rfc8493.html). La herramienta solo implementa SHA-256, UTF-8 y este índice: **no es un validador general ni una implementación completa de RFC 8493**. Puede rechazar bolsas BagIt válidas con algoritmos, etiquetas, nombres o metadatos fuera del perfil.

Se usa la biblioteca estándar para mantener un runtime pequeño. [bagit-python](https://github.com/LibraryOfCongress/bagit-python) es una alternativa general y se utiliza solo como verificador independiente opcional de los ejemplos producidos; no se copia ni se incorpora su código al paquete.

## Desarrollo local

La suite básica usa exclusivamente `unittest`:

```sh
python -m pip install -e .
python -m unittest discover -s tests -v
```

Las pruebas usan archivos sintéticos temporales e incluyen alteraciones de contenido, referencias ausentes, índices duplicados, rutas ambiguas, colisiones, enlaces, límites y fallos parciales de creación. No constituyen certificación de seguridad ni de conformidad BagIt completa.

No se configura CI remota en esta versión inicial. Consulta [la verificación local](docs/verificacion.md) para comandos y alcance.
