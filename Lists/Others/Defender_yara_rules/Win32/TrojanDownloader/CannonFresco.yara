rule TrojanDownloader_Win32_CannonFresco_B_2147787450_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/CannonFresco.B!dha"
        threat_id = "2147787450"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "CannonFresco"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mkdir %appdata%\\systemUpdating & powershell -w 1 -nologo -ec" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

