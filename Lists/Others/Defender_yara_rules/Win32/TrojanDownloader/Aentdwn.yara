rule TrojanDownloader_Win32_Aentdwn_B_2147725104_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Aentdwn.B!bit"
        threat_id = "2147725104"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Aentdwn"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 00 36 00 35 00 2e 00 32 00 32 00 37 00 2e 00 31 00 35 00 33 00 2e 00 31 00 38 00 31 00 2f 00 [0-47] 75 00 70 00 64 00 61 00 74 00 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = "CGIFastSQL.exe" wide //weight: 1
        $x_1_3 = "Sql.bat" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Aentdwn_G_2147727882_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Aentdwn.G!bit"
        threat_id = "2147727882"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Aentdwn"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {35 00 2e 00 32 00 30 00 30 00 2e 00 35 00 32 00 2e 00 35 00 31 00 [0-47] 64 00 61 00 74 00 61 00}  //weight: 1, accuracy: Low
        $x_1_2 = {73 00 74 00 61 00 72 00 74 00 [0-47] 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

