rule TrojanDownloader_Win32_Terdot_A_2147711575_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Terdot.A"
        threat_id = "2147711575"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Terdot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {a8 01 74 09 d1 e8 35 20 83 b8 ed eb 02 d1 e8 4e 75 ee}  //weight: 1, accuracy: High
        $x_1_2 = {0f b6 04 32 33 c1 25 ff 00 00 00 c1 e9 08 33 0c 85 ?? ?? ?? ?? 42 3b 54 24 0c 72 e4}  //weight: 1, accuracy: Low
        $x_1_3 = {5f 52 75 6e 40 34 00 00 73 68 61 72 65 64 5f}  //weight: 1, accuracy: High
        $x_1_4 = {72 00 75 00 6e 00 61 00 73 00 00 00 77 00 6d 00 69 00 63 00 00 00 00 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 63 00 61 00 6c 00 6c 00 20 00 63 00 72 00 65 00 61 00 74 00 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 65 00 78 00 65 00 00 00 00 00 52 75 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

