rule TrojanDownloader_Win64_Brucryp_B_2147697092_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Brucryp.B"
        threat_id = "2147697092"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Brucryp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "4d5a90000300000004000000ffff" ascii //weight: 1
        $x_1_2 = "420fb6042249ffc0ffc1418840ff48ffc248ffcf75e0458bc34d8bcb448d574090420fb6540c60420fb64c0d604983c1" ascii //weight: 1
        $x_1_3 = {0f b6 42 ff 0f b6 0a 3c 61 7c 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win64_Brucryp_E_2147709421_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Brucryp.E"
        threat_id = "2147709421"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Brucryp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 f7 f2 42 0f b6 04 1a 41 2a 00 41 88 00 ff c6 4d 8d 40 01 41 3b f1 72 e3}  //weight: 1, accuracy: High
        $x_1_2 = {41 f7 f2 42 0f b6 04 1a 41 2a 00 41 88 00 41 ff c6 4d 8d 40 01 45 3b f1 72 e1}  //weight: 1, accuracy: High
        $x_2_3 = {41 b8 2a 0a 00 00 48 8b c8 e8 ?? ?? ?? ?? ?? ?? ?? ?? ?? 41 b8 14 05 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

