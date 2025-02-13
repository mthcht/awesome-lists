rule TrojanClicker_Win32_Collicky_A_2147684371_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Collicky.A"
        threat_id = "2147684371"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Collicky"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WEBCC[" ascii //weight: 1
        $x_1_2 = "WXCC[" ascii //weight: 1
        $x_1_3 = "BTCC[" ascii //weight: 1
        $x_1_4 = "726E6E6A203535" ascii //weight: 1
        $x_1_5 = {8a 55 e7 80 f2 21 32 c2 88 45 e6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

