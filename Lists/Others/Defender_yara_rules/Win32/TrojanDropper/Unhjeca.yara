rule TrojanDropper_Win32_Unhjeca_A_2147637642_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Unhjeca.A"
        threat_id = "2147637642"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Unhjeca"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 48 08 88 50 0c 33 c0 85 f6 7e 09 80 34 38 2a 40 3b c6 7c f7}  //weight: 1, accuracy: High
        $x_1_2 = {6a 61 76 61 20 2d 6a 61 72 20 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

