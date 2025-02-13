rule TrojanDownloader_Win32_CmdSecurityWid_B_2147777969_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/CmdSecurityWid.B!dha"
        threat_id = "2147777969"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "CmdSecurityWid"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "icacls" wide //weight: 1
        $x_1_2 = {5c 00 5c 00 3f 00 5c 00 ?? ?? 3a 00 5c 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 64 00 61 00 74 00 61 00 5c 00 63 00 6f 00 6d 00 5c 00}  //weight: 1, accuracy: Low
        $x_1_3 = "/inheritance:r" wide //weight: 1
        $x_1_4 = "/grant:r" wide //weight: 1
        $x_1_5 = "system:" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

