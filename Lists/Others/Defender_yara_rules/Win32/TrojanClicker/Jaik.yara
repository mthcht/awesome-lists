rule TrojanClicker_Win32_Jaik_MBXU_2147923431_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Jaik.MBXU!MTB"
        threat_id = "2147923431"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Jaik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {40 00 44 84 40 00 48 80 40 00 14 7a 40 00 d4 8a 40 00}  //weight: 2, accuracy: High
        $x_1_2 = {48 19 40 00 5f fc 38 01 00 ff ff ff 08 00 00 00 01 00 00 00 03 00 01 00 e9 00 00 00 58 15 40 00 98 17 40 00 14 11 40 00 78 00 00 00 80 00 00 00 87}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

