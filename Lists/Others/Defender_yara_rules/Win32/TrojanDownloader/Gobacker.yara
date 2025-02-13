rule TrojanDownloader_Win32_Gobacker_A_2147628898_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Gobacker.A"
        threat_id = "2147628898"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Gobacker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {66 60 0f 31 69 d0 05 84 08 08 42 8b 44 24 24 f7 e2}  //weight: 4, accuracy: High
        $x_1_2 = {2f 73 6f 63 6b 73 2f 64 6f 69 74 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_3 = {25 73 3f 70 6f 72 74 3d 25 64 00}  //weight: 1, accuracy: High
        $x_1_4 = {5f 4b 49 4c 4c 5f 00}  //weight: 1, accuracy: High
        $x_1_5 = {5f 55 50 44 41 54 45 5f 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

