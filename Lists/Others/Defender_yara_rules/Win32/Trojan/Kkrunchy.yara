rule Trojan_Win32_Kkrunchy_GVB_2147949372_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kkrunchy.GVB!MTB"
        threat_id = "2147949372"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kkrunchy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 06 0f b6 50 01 0f b6 00 8a 4d 1c fe c6 8b 04 85 05 3b a7 00 d3 ea 19 c9 31 c8 29 c8 3b 55 14 74 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

