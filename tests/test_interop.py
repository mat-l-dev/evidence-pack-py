"""Optional independent BagIt check; install bagit==1.9.0 to enable."""

import importlib.util
import tempfile
import unittest
from pathlib import Path

from evidence_pack import create_pack


@unittest.skipUnless(importlib.util.find_spec("bagit"), "Optional verifier bagit is not installed")
class BagItInteropTests(unittest.TestCase):
    def test_generated_bag_passes_independent_verifier(self):
        import bagit

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source = root / "source"
            source.mkdir()
            (source / "área común").mkdir()
            (source / "área común" / "nota.txt").write_text(
                "Ejemplo sintético.\n", encoding="utf-8"
            )
            (source / "empty.bin").write_bytes(b"")
            (source / "binary.bin").write_bytes(b"\x00\xff\r\n")
            pack = root / "pack"
            create_pack(source, pack, {"F1": ["área común/nota.txt", "empty.bin"]})
            self.assertTrue(bagit.Bag(str(pack)).validate())


if __name__ == "__main__":
    unittest.main()
