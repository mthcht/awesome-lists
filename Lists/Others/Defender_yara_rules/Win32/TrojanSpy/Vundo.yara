rule TrojanSpy_Win32_Vundo_A_2147603211_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Vundo.A"
        threat_id = "2147603211"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Vundo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 48 04 c7 00 64 74 72 52 89 50 08 a3}  //weight: 1, accuracy: High
        $x_1_2 = {74 70 66 81 7e 1c 44 65 74 68}  //weight: 1, accuracy: High
        $x_1_3 = {66 c7 46 1c 44 65 66 c7 46 1e 74 6f 66 c7 46 20 75 72 66 c7 46 22 73 21}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

