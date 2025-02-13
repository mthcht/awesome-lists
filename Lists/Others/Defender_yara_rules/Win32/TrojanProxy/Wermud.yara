rule TrojanProxy_Win32_Wermud_A_2147626924_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Wermud.A"
        threat_id = "2147626924"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Wermud"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 c6 20 03 00 00 81 e9 20 03 00 00 81 fe 00 00 00 05}  //weight: 1, accuracy: High
        $x_1_2 = {be 00 00 30 00 57 c7 44 24 10 00 00 00 00 89 74 24 1c 8d 44 24 10 8d 4c 24 28 50 68 00 04 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {6a 04 68 00 10 00 00 68 a4 01 00 00 6a 00 56 ff d7 8b d8 85 db 75 0b}  //weight: 1, accuracy: High
        $x_1_4 = {b1 74 b3 70 b2 3a 50 57 c7 45 00 00 00 00 00 33 f6 c6 44 24 20 68}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

