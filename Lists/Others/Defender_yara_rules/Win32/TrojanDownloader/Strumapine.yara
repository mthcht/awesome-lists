rule TrojanDownloader_Win32_Strumapine_A_2147706738_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Strumapine.A"
        threat_id = "2147706738"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Strumapine"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {d3 ef 8b cf f6 d1 32 d9}  //weight: 1, accuracy: High
        $x_1_2 = {8b 04 24 83 c0 05 c3}  //weight: 1, accuracy: High
        $x_1_3 = {88 14 01 48 83 f8 ff 75 e7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Strumapine_B_2147714796_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Strumapine.B"
        threat_id = "2147714796"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Strumapine"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 44 24 16 75 c6 44 24 17 74 c6 44 24 18 65 c6 44 24 19 41 c6 44 24 1a 00 c6 44 24 08 6f c6 44 24 09 70 c6 44 24 0a 65 c6 44 24 0b 6e c6 44 24 0c 00 68}  //weight: 1, accuracy: High
        $x_1_2 = "Microsoft\\JavaSetup" wide //weight: 1
        $x_1_3 = {00 00 61 00 2e 00 68 00 6c 00 70 00 00 00 68 74 74 70 3a 2f 2f 77 69 6e 72 61 72 2e 66 72 65 65 64 6f 77 6e 6c 6f 61 64 2e 63 6e 74 2e 62 72 2f}  //weight: 1, accuracy: High
        $x_1_4 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 50 00 69 00 6e 00 5f 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

