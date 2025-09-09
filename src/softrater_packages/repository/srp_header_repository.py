"""Repository for handling SRP Header XML data."""

import shutil
import uuid
from pathlib import Path

import pyzipper
import xmltodict

from softrater_packages.config import get_config
from softrater_packages.entities.srp_request import Srp


class SrpHeaderRepository:
    """Repository for handling SRP Header XML data."""

    _NO_ARG = object()
    # Define attribute maps per entity
    ATTRIBUTE_MAPS = {
        "SrpHeader": {
            "module_request": "srpheader",
            "@schema": "schema",
            "pk": "prog_key",
            "build_type": "build_type",
            "location": "location",
            "carrier_id": "carrier_id",
            "carrier_name": "carrier_name",
            "line_id": "line_id",
            "line_desc": "line_desc",
            "schema_id": "schema_id",
            "program_id": "program_id",
            "program_name": "program_name",
            "version_desc": "version_desc",
            "program_version": "program_version",
            "parent_company": "parent_company",
            "notes": "notes",
        },
        "Srp": {
            "param": "srpuser",
            "module_request": "srpheader",
        },
        "SrpRequestUser": {
            "param": "srpuser",
            "@user_name": "user_name",
            "@fullname": "full_name",
            "@email_address": "email_address",
        },
    }

    @staticmethod
    def _srp_request_header_to_export_header(req: Srp) -> dict:
        """Convert SrpRequest to export header dictionary."""
        header_export = {
            "export": {
                "template": {
                    "header": {
                        "l": req.srpheader.line_id,
                        "schema": req.srpheader.schema_id,
                        "product": req.srpheader.line_id,
                        "pd": req.srpheader.line_desc,
                        "p": req.srpheader.program_id,
                        "v": req.srpheader.program_version,
                        "d": req.srpheader.program_name,
                        "n": req.srpheader.notes or "0",
                        "vd": req.srpheader.version_desc or "",
                        "ld": req.srpheader.line_desc,
                        "s": req.srpheader.schema or "-2",
                        "sd": "",
                        "ti": req.srpheader.prog_key,
                        "tv": uuid.uuid4().hex,
                        "tk": uuid.uuid4().hex,
                        "dfc": "1",
                        "nfc": "0",
                        "au": "0",
                        "cvu": "0",
                        "mvu": "0",
                        "date_created": req.srpheader.date_created or "",
                        "ef": (req.srpheader.prog_key or "") + ".xml",
                        "template_type": "EXPORT_READ_WRITE",
                    }
                }
            }
        }

        return header_export

    @staticmethod
    def _entity_aware_postprocessor(path, key, value=_NO_ARG):
        # Unwrap {"item": {...}} at any level
        if isinstance(value, dict) and set(value.keys()) == {"item"}:
            value = value["item"]

        attr_map = {}
        # Determine the entity type based on the path
        if path and isinstance(path[-1], tuple):
            parent = path[-1][0]

            if parent in {"module_request", "param"}:
                attr_map = SrpHeaderRepository.ATTRIBUTE_MAPS.get("Srp", {})

            mapped_key = attr_map.get(key, key)

            if mapped_key == "srpheader":
                # value is already the steps list/dict
                if isinstance(value, dict):
                    # Single dependency
                    value = {SrpHeaderRepository.ATTRIBUTE_MAPS["SrpHeader"].get(k, k): v for k, v in value.items()}
            elif mapped_key == "srpuser":
                # value is already the steps list/dict
                value = value["idn_user"]
                if isinstance(value, list):
                    # Single dependency
                    value = {
                        SrpHeaderRepository.ATTRIBUTE_MAPS["SrpRequestUser"].get(k, k): v for k, v in value[0].items()
                    }

            return mapped_key, value

    @staticmethod
    def get_srp_header(xml_file: str) -> Srp | None:
        print(f"Reading SRP Header from XML file: {xml_file}")

        config = get_config()

        with open(xml_file, encoding="utf-8") as f:
            doc = xmltodict.parse(
                f.read(),
                force_list=("idn_user"),
                postprocessor=SrpHeaderRepository()._entity_aware_postprocessor,
            )

        srp_header_data = doc.get("env", {})

        if srp_header_data is None:
            return None

        srp_header = Srp.model_validate(srp_header_data)

        tree = SrpHeaderRepository()._srp_request_header_to_export_header(srp_header)

        xml_str = xmltodict.unparse(
            tree,
            pretty=True,
            indent="  ",
            full_document=True,  # adds XML declaration
        )

        dest = (
            Path(xml_file).parent
            / "export"
            / str(srp_header.srpheader.line_desc)
            / str(srp_header.srpheader.program_name)
            / str(srp_header.srpheader.date_created).replace(" ", "_").replace("/", "_")
            / "header.xml"
        )

        dest.parent.mkdir(parents=True, exist_ok=True)

        SrpHeaderRepository().move_files_flat(Path(xml_file).parent, dest.parent, overwrite=True)
        SrpHeaderRepository().move_files_flat(Path(Path(xml_file).parent / "rtd"), dest.parent, overwrite=True)
        SrpHeaderRepository().move_files_flat(Path(Path(xml_file).parent / "rto"), dest.parent, overwrite=True)

        dest.write_text(xml_str, encoding="utf-8")

        SrpHeaderRepository().zip_directory(
            dest.parent,
            dest.parent.with_suffix(".srtp"),
            config.ingest.zip_password if config.ingest else None,
        )
        print(f"SRP Header parsed successfully: {srp_header.model_dump()}")

        # optionally remove the now-empty subdir
        try:
            dest.parent.rmdir()
        except OSError:
            pass

        return srp_header

    @staticmethod
    def move_files_flat(src_subdir: Path, export_dir: Path, overwrite: bool = True) -> None:
        for fp in src_subdir.iterdir():  # no recursion needed
            if fp.is_file():
                dest = export_dir / fp.name
                if dest.exists() and overwrite:
                    dest.unlink()  # overwrite existing file
                shutil.move(str(fp), str(dest))

        # optionally remove the now-empty subdir
        try:
            src_subdir.rmdir()
        except OSError:
            pass

    @staticmethod
    def zip_directory(export_dir: Path, zip_path: Path, password: str | None = None) -> Path:
        """Zip all files under export_dir into zip_path.
        If password is given, uses ZipCrypto (zipfile limitation).
        """
        export_dir, zip_path = Path(export_dir), Path(zip_path)
        zip_path.parent.mkdir(parents=True, exist_ok=True)

        with pyzipper.AESZipFile(zip_path, "w", compression=pyzipper.ZIP_DEFLATED) as zf:
            # set AES encryption + password
            if password:
                zf.setpassword(password.encode("utf-8"))
                zf.setencryption(pyzipper.WZ_AES, nbits=256)

            for fp in export_dir.rglob("*"):
                if fp.is_file():
                    zf.write(fp, arcname=fp.relative_to(export_dir))
        return zip_path

    @staticmethod
    def cleanup_directory(path: Path) -> None:
        """Delete a directory tree if it exists."""
        shutil.rmtree(path, ignore_errors=True)
