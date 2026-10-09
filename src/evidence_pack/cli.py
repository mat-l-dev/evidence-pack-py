"""Small JSON-output command-line interface."""

import argparse
import json
from collections.abc import Sequence
from dataclasses import asdict

from .core import create_pack, load_findings, verify_pack
from .models import EvidencePackError


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Crear y verificar un paquete local de evidencia.")
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create", help="Copiar una carpeta estable a un destino nuevo")
    create.add_argument("source", help="Carpeta de archivos originales")
    create.add_argument("destination", help="Carpeta nueva; su padre debe existir")
    create.add_argument(
        "--findings", required=True, help="JSON: IDs de hallazgo a rutas relativas al origen"
    )
    verify = commands.add_parser(
        "verify", help="Verificar el perfil evidence-pack/1 sin modificarlo"
    )
    verify.add_argument("pack", help="Carpeta del paquete")
    args = parser.parse_args(argv)
    try:
        if args.command == "create":
            report = create_pack(args.source, args.destination, load_findings(args.findings))
        else:
            report = verify_pack(args.pack)
        print(json.dumps(report.to_dict(), ensure_ascii=False, sort_keys=True, indent=2))
        return 0 if report.valid else 1
    except EvidencePackError as exc:
        print(
            json.dumps(
                {"valid": False, "issues": [asdict(exc.issue)]},
                ensure_ascii=False,
                sort_keys=True,
                indent=2,
            )
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
