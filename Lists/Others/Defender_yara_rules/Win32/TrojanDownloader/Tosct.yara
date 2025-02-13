rule TrojanDownloader_Win32_Tosct_A_2147654408_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tosct.A"
        threat_id = "2147654408"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tosct"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c8 b0 65 c6 44 0c 10 2e 88 44 0c 11 c6 44 0c 12 78 88 44 0c 13 c6 44 0c 14 00 eb}  //weight: 1, accuracy: High
        $x_1_2 = {8a 02 3c 65 75 05 83 ce ff eb 0e 2c 66 f6 d8 1b c0 83 e0 0c 83 c0 fe 8b f0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Tosct_B_2147654495_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tosct.B"
        threat_id = "2147654495"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tosct"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 48 01 40 84 c9 75 f8 8a 08 80 f9 5c 74 0d 3a ca 74 09 8a 48 ff 48 80 f9 5c 75 f3}  //weight: 1, accuracy: High
        $x_1_2 = {c6 04 28 00 8a 45 00 83 c4 0c 3c 73 0f 84 ?? 01 00 00 3c 53 0f 84 ?? 01 00 00 3c 64 0f 84 ?? 01 00 00 3c 44 0f 84 ?? 01 00 00 3c 72 74 ?? 3c 52 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

