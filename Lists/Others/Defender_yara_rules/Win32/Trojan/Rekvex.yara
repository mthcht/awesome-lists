rule Trojan_Win32_Rekvex_AO_2147817224_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rekvex.AO!MTB"
        threat_id = "2147817224"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rekvex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 4d f8 c1 e1 03 d3 ee 33 d6 8b 45 f8 8b 4d 08 8d 04 81 8b 4d f4 88 14 08 eb 97}  //weight: 2, accuracy: High
        $x_2_2 = {33 45 f8 8b 4d fc 8b 55 08 89 44 8a 18 e9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

