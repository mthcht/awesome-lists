rule Trojan_Win32_MortyStealer_MA_2147895545_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MortyStealer.MA!MTB"
        threat_id = "2147895545"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MortyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c0 66 89 44 24 16 8b 41 08 89 44 24 18 8b 41 0c 8b 4c 24 34 89 44 24 1c 0f b6 c1 66 c1 e0 08 66 89 44 24 20 8b c1 c1 e8 08 0f b6 c0 66 c1 e0 08 66 89 44 24 22 c1 e9 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

