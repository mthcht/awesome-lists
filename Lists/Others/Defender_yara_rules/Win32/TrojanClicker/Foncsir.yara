rule TrojanClicker_Win32_Foncsir_A_2147628589_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Foncsir.A"
        threat_id = "2147628589"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Foncsir"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 52 50 8b c3 99 29 04 24 19 54 24 04 58 5a 83 fa 00 75 09 3d ?? ?? ?? ?? 72 df}  //weight: 1, accuracy: Low
        $x_1_2 = {5b 6c 69 6e 6b 73 5d 00}  //weight: 1, accuracy: High
        $x_1_3 = {5b 73 65 61 72 63 68 65 73 5d 00}  //weight: 1, accuracy: High
        $x_1_4 = {2f 63 6f 6e 66 2e 70 68 70 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

