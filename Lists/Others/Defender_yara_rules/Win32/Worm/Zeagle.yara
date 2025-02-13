rule Worm_Win32_Zeagle_A_2147649990_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Zeagle.A"
        threat_id = "2147649990"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Zeagle"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff 51 38 ff 45 f8 ff 4d f4 75 b9 8d 55 e0 b8}  //weight: 1, accuracy: High
        $x_1_2 = {fe 45 f3 80 7d f3 5b 0f}  //weight: 1, accuracy: High
        $x_1_3 = {3c 01 75 3c 8d 45 b0 50 8d 55 a8 8b 45 f8 e8}  //weight: 1, accuracy: High
        $x_1_4 = {6a 6f 65 62 6f 78 63 6f 6e 74 72 6f 6c 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {64 69 72 5f 77 61 74 63 68 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_6 = {77 65 62 64 6f 77 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

