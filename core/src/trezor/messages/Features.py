# Automatically generated by pb2py
# fmt: off
import protobuf as p

if __debug__:
    try:
        from typing import Dict, List  # noqa: F401
        from typing_extensions import Literal  # noqa: F401
        EnumTypeCapability = Literal[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17]
        EnumTypeBackupType = Literal[0, 1, 2]
    except ImportError:
        pass


class Features(p.MessageType):
    MESSAGE_WIRE_TYPE = 17

    def __init__(
        self,
        vendor: str = None,
        major_version: int = None,
        minor_version: int = None,
        patch_version: int = None,
        bootloader_mode: bool = None,
        device_id: str = None,
        pin_protection: bool = None,
        passphrase_protection: bool = None,
        language: str = None,
        label: str = None,
        initialized: bool = None,
        revision: bytes = None,
        bootloader_hash: bytes = None,
        imported: bool = None,
        pin_cached: bool = None,
        passphrase_cached: bool = None,
        firmware_present: bool = None,
        needs_backup: bool = None,
        flags: int = None,
        model: str = None,
        fw_major: int = None,
        fw_minor: int = None,
        fw_patch: int = None,
        fw_vendor: str = None,
        fw_vendor_keys: bytes = None,
        unfinished_backup: bool = None,
        no_backup: bool = None,
        recovery_mode: bool = None,
        capabilities: List[EnumTypeCapability] = None,
        backup_type: EnumTypeBackupType = None,
        sd_card_present: bool = None,
        sd_protection: bool = None,
        session_id: bytes = None,
    ) -> None:
        self.vendor = vendor
        self.major_version = major_version
        self.minor_version = minor_version
        self.patch_version = patch_version
        self.bootloader_mode = bootloader_mode
        self.device_id = device_id
        self.pin_protection = pin_protection
        self.passphrase_protection = passphrase_protection
        self.language = language
        self.label = label
        self.initialized = initialized
        self.revision = revision
        self.bootloader_hash = bootloader_hash
        self.imported = imported
        self.pin_cached = pin_cached
        self.passphrase_cached = passphrase_cached
        self.firmware_present = firmware_present
        self.needs_backup = needs_backup
        self.flags = flags
        self.model = model
        self.fw_major = fw_major
        self.fw_minor = fw_minor
        self.fw_patch = fw_patch
        self.fw_vendor = fw_vendor
        self.fw_vendor_keys = fw_vendor_keys
        self.unfinished_backup = unfinished_backup
        self.no_backup = no_backup
        self.recovery_mode = recovery_mode
        self.capabilities = capabilities if capabilities is not None else []
        self.backup_type = backup_type
        self.sd_card_present = sd_card_present
        self.sd_protection = sd_protection
        self.session_id = session_id

    @classmethod
    def get_fields(cls) -> Dict:
        return {
            1: ('vendor', p.UnicodeType, 0),
            2: ('major_version', p.UVarintType, 0),
            3: ('minor_version', p.UVarintType, 0),
            4: ('patch_version', p.UVarintType, 0),
            5: ('bootloader_mode', p.BoolType, 0),
            6: ('device_id', p.UnicodeType, 0),
            7: ('pin_protection', p.BoolType, 0),
            8: ('passphrase_protection', p.BoolType, 0),
            9: ('language', p.UnicodeType, 0),
            10: ('label', p.UnicodeType, 0),
            12: ('initialized', p.BoolType, 0),
            13: ('revision', p.BytesType, 0),
            14: ('bootloader_hash', p.BytesType, 0),
            15: ('imported', p.BoolType, 0),
            16: ('pin_cached', p.BoolType, 0),
            17: ('passphrase_cached', p.BoolType, 0),
            18: ('firmware_present', p.BoolType, 0),
            19: ('needs_backup', p.BoolType, 0),
            20: ('flags', p.UVarintType, 0),
            21: ('model', p.UnicodeType, 0),
            22: ('fw_major', p.UVarintType, 0),
            23: ('fw_minor', p.UVarintType, 0),
            24: ('fw_patch', p.UVarintType, 0),
            25: ('fw_vendor', p.UnicodeType, 0),
            26: ('fw_vendor_keys', p.BytesType, 0),
            27: ('unfinished_backup', p.BoolType, 0),
            28: ('no_backup', p.BoolType, 0),
            29: ('recovery_mode', p.BoolType, 0),
            30: ('capabilities', p.EnumType("Capability", (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17)), p.FLAG_REPEATED),
            31: ('backup_type', p.EnumType("BackupType", (0, 1, 2)), 0),
            32: ('sd_card_present', p.BoolType, 0),
            33: ('sd_protection', p.BoolType, 0),
            34: ('session_id', p.BytesType, 0),
        }
