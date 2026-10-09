# Verificación local

Estado de la primera entrega, 9 de octubre de 2026. Entorno ejecutado: Linux x86_64, Python 3.12.14 y uv 0.12.23. No se ejecutó CI remota ni se probaron Windows/macOS.

## Reproducción

Las herramientas de desarrollo están fijadas en `pyproject.toml` y `uv.lock`; no forman parte de las dependencias de ejecución.

```sh
uv sync --locked --group dev
uv run --locked ruff check src tests
uv run --locked ruff format --check src tests
uv run --locked mypy --strict src
uv run --locked python -m coverage run --branch --source=evidence_pack -m unittest discover -s tests -v
uv run --locked python -m coverage report -m
uv build
```

En una máquina donde el caché de uv predeterminado no sea escribible, establece `UV_CACHE_DIR` en una carpeta escribible local. El caché no pertenece a la distribución.

## Resultados

- 50 pruebas ejecutadas y aprobadas, incluido el verificador opcional externo `bagit==1.9.0`.
- Ruff: sin incidencias; formato verificado.
- Mypy estricto: sin incidencias en los seis módulos fuente.
- Cobertura local con ramas: 92 %. Es una medida de ejecución de la suite, no una garantía de corrección.
- Distribuciones sdist y wheel creadas localmente; sin publicación a un índice de paquetes.
- El CLI instalado desde el wheel crea y verifica el ejemplo, sin depender del checkout para importar la biblioteca.

Si se ejecuta únicamente la suite básica con la biblioteca estándar, la comprobación externa se omite cuando `bagit` no está instalado. Esta omisión se indica como `skipped`; no debe contarse como una comprobación externa aprobada.

La prueba externa usa una bolsa sintética con nombres Unicode, un subdirectorio, un archivo vacío y contenido binario. Demuestra interoperabilidad de ese caso producido; no significa que se hayan ejecutado todos los casos de conformidad de RFC 8493 ni que la herramienta acepte cualquier bolsa BagIt.

## Límites de estas pruebas

Los casos de rutas, enlaces y cambios de contenido son fixtures locales ordinarios. No se ejecuta contenido de evidencia ni se accede a sistemas ajenos. No se prueba una sandbox frente a escritores hostiles concurrentes, resistencia a caída eléctrica, todos los sistemas de archivos o firmas/custodia legal.

La creación usa nombres exclusivos y deja visibles los intentos parciales para inspección. La política completa está en [perfil.md](perfil.md).
