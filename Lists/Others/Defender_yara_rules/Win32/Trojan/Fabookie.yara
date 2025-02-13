rule Trojan_Win32_Fabookie_RZ_2147852195_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fabookie.RZ!MTB"
        threat_id = "2147852195"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fabookie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 04 24 00 00 00 00 8b 44 24 10 89 04 24 8b 44 24 0c 31 04 24 8b 04 24 8b 4c 24 08 89 01 59 c2 0c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

