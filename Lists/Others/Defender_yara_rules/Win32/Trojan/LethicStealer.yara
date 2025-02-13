rule Trojan_Win32_LethicStealer_RPN_2147840234_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LethicStealer.RPN!MTB"
        threat_id = "2147840234"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LethicStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 0a 88 dd d2 e5 00 e9 88 08 0f b6 4d fc 89 d8 d3 f8 0f b6 4d fc 29 c1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

