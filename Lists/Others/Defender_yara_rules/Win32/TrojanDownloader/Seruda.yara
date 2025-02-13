rule TrojanDownloader_Win32_Seruda_A_2147682387_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Seruda.A"
        threat_id = "2147682387"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Seruda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {56 49 50 52 45 00 00 00 53 42 41 4d 53 76 63 2e 65 78 65 00 4d 69 63 72 6f 73 6f 66 74 20 53 65 63 75 72 69 74 79 20 45 73 73 65 6e 74 69 61 6c 73 00 00 00 4d 73 4d 70 45 6e 67 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {bf fa 00 00 00 99 8b cf f7 f9 42 52 ff d3 99 8b cf f7 f9 42 52 ff d3 99 8b cf f7 f9 42 52 ff d3 99 f7 ff 8d 45 a4}  //weight: 1, accuracy: High
        $x_1_3 = {f7 f9 8a c2 8a c8 8a e9 8b c1 c1 e0 10 66 8b c1 b9 fe 03 00 00 4e f3 ab 75}  //weight: 1, accuracy: High
        $x_1_4 = {f7 f9 6a 00 68 00 04 00 00 8a c2 8a c8 8a e9 8b c1 c1 e0 10 66 8b c1 b9 00 01 00 00 f3 ab}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

