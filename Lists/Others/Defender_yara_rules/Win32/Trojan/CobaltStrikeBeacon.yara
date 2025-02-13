rule Trojan_Win32_CobaltStrikeBeacon_AA_2147841090_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrikeBeacon.AA!MTB"
        threat_id = "2147841090"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrikeBeacon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 04 24 ff c0 89 04 24 8b 44 24 28 39 04 24 73 20 8b 04 24 0f b6 4c 24 30 48 8b 54 24 20 0f be 04 02 33 c1 8b 0c 24 48 8b 54 24 20 88 04 0a eb cf}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CobaltStrikeBeacon_ZY_2147843882_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobaltStrikeBeacon.ZY!MTB"
        threat_id = "2147843882"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrikeBeacon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 d1 83 e1 07 8a 0c 08 30 0c 16 42 83 fa 40 75 ef 31 d2 3b 55 0c 7d 0e 89 d1 83 e1 07 8a 0c 08 30 0c 13 42 eb ed}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

