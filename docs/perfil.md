# Perfil evidence-pack/1

Este documento describe el contrato de la versión 0.1.0. Las restricciones son decisiones de este paquete y no pretenden redefinir BagIt.

## Estructura cerrada

La raíz contiene exactamente cuatro archivos: `bagit.txt`, `manifest-sha256.txt`, `tagmanifest-sha256.txt` e `index.json`, y el directorio `data`. Dentro de `data` se admiten subdirectorios y archivos regulares sujetos a la política de rutas. No se admite `fetch.txt`, `bag-info.txt`, otro algoritmo ni etiquetas adicionales.

La declaración de creación es UTF-8 sin BOM y termina cada línea con LF:

```text
BagIt-Version: 1.0
Tag-File-Character-Encoding: UTF-8
```

La lectura acepta también CRLF para esta declaración. Su contenido, orden y capitalización son exactos para este perfil.

Los manifiestos se crean con un SHA-256 hexadecimal en minúscula, dos espacios y una ruta relativa por línea, ordenada por cadena Unicode. La lectura permite mayúsculas en el hash, uno o más espacios/tabulaciones como separador, y finales de línea LF, CRLF o CR. No se aceptan líneas vacías interiores ni rutas duplicadas. El salto final puede omitirse al leer.

Cada archivo del payload debe figurar exactamente una vez en el manifiesto principal. El manifiesto de etiquetas debe listar exactamente los otros tres archivos de raíz; no se lista a sí mismo. Todos los hashes se calculan sobre bytes sin decodificación del contenido.

## Índice JSON

El índice es un archivo UTF-8 sin BOM con exactamente dos claves: `profile` y `findings`. `profile` debe ser `evidence-pack/1`. No se aceptan claves JSON repetidas, aunque sus valores sean iguales. No se aceptan campos extra.

`findings` es un objeto no vacío. Cada clave debe cumplir `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`; los IDs distinguen mayúsculas de minúsculas. Cada valor es una lista no vacía de rutas únicas, relativas a la raíz y que comienzan por `data/`. Cada ruta debe identificar un archivo regular existente del payload.

El mismo archivo puede figurar en varios hallazgos. Un archivo puede no figurar en ningún hallazgo: su integridad sigue siendo verificada y `referenced_files` hace visible cuántos archivos distintos están vinculados. El índice no guarda valoraciones, atribuciones ni conclusiones acerca de los archivos.

La entrada de `create_pack` y el JSON de `--findings` tienen solamente el objeto de hallazgos. Sus rutas son relativas al directorio de origen y no llevan el prefijo `data/`; la biblioteca lo agrega al escribir.

## Nombres y límites

- Rutas UTF-8 ya normalizadas a NFC; no se normalizan ni renombran automáticamente.
- Cada componente es no vacío, no es `.` ni `..`, y no empieza/termina en espacio en blanco ni termina en punto.
- No se admiten `\\`, `%`, `<`, `>`, `:`, `"`, `|`, `?`, `*`, caracteres de categorías Unicode `C*`, separadores de línea o párrafo.
- Se rechazan los nombres de dispositivo reservados de Windows incluidos en la política, también con extensión.
- Se rechazan nombres de hermanos que colisionen bajo Unicode casefold, tanto archivos como directorios.
- Máximo de 255 bytes UTF-8 por componente, 4096 bytes por ruta relativa y 64 componentes. El prefijo `data/` cuenta en el límite de salida.
- Máximo de 100 000 entradas de filesystem por árbol inspeccionado, contando archivos y directorios. La creación reserva el espacio para las etiquetas y directorios de salida antes de copiar.
- Índice: máximo de 1 MiB. Cada manifiesto: máximo de 16 MiB. Declaración: máximo de 1024 bytes.
- El contenido se copia y resume en bloques de 1 MiB. No hay límite propio al tamaño de un archivo; espacio en disco y límites del sistema siguen aplicando. Inventario, índice y manifiestos se mantienen en memoria hasta sus límites.

Un sistema operativo puede imponer límites inferiores. En ese caso se informa el error de E/S. Los directorios vacíos del origen no se reproducen; los que ya existan dentro de `data` no aportan contenido al manifiesto.

## Creación y fallo

1. Valida el origen, el índice, el destino y los límites derivados.
2. Reserva un destino inexistente con creación exclusiva de directorio.
3. Copia los bytes a archivos creados de forma exclusiva y calcula SHA-256.
4. Vuelve a inventariar el origen para detectar cambios ordinarios.
5. Escribe índice y manifiestos; escribe la declaración en último lugar.
6. Verifica la salida antes de informar éxito.

No reutiliza ni sobrescribe un destino anterior. No elimina archivos de un intento fallido. Los directorios parciales quedan visibles mientras se escribe; la aparición de `bagit.txt` no sustituye la verificación del paquete completo. No se ofrecen recuperación automática, bloqueo de otros procesos, protección frente a cambios hostiles concurrentes, restauración de permisos ni persistencia mediante `fsync`.

Los enlaces simbólicos, puntos de reanálisis, hard links, sockets, FIFO y dispositivos no pertenecen al perfil. Se revisan también los ancestros de los argumentos raíz. Esa revisión requiere que las rutas permanezcan estables; no constituye una sandbox del sistema de archivos.

## Qué establece un informe válido

La estructura y las referencias coinciden con el perfil, y los bytes leídos coinciden con los hashes guardados. No establece la identidad de quien produjo el paquete, la integridad de un manifiesto recibido por un canal no confiable, la veracidad del contenido ni una fecha cierta.

Una firma independiente, una custodia documentada o la validación del contenido requieren mecanismos externos elegidos por el consumidor. Esta biblioteca no los implementa ni afirma sustituirlos.

## Referencias

- [RFC 8493: estructura, manifiestos y alcance de BagIt](https://www.rfc-editor.org/rfc/rfc8493.html).
- [bagit-python de Library of Congress](https://github.com/LibraryOfCongress/bagit-python): verificador externo opcional, sin dependencia de runtime ni código vendorizado.
- [Python: operaciones de archivos](https://docs.python.org/3.12/library/os.html): las capacidades y errores concretos dependen del sistema operativo.
