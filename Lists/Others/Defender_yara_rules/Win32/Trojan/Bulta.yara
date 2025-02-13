rule Trojan_Win32_Bulta_RPH_2147829270_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bulta.RPH!MTB"
        threat_id = "2147829270"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bulta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 44 24 1c 8b 44 24 1c 89 44 24 18 8b 44 24 14 8b 4c 24 20 d3 e8 89 44 24 10 8b 44 24 3c 01 44 24 10 8b 4c 24 10 33 4c 24 18}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bulta_RPY_2147853022_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bulta.RPY!MTB"
        threat_id = "2147853022"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bulta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 4c 24 20 8b d0 c1 ea 05 03 54 24 24 03 c5 33 d1 33 d0 2b fa 8b cf c1 e1 04 81 3d}  //weight: 1, accuracy: High
        $x_1_2 = {8b 84 24 74 08 00 00 8b 54 24 14 89 78 04 5f 5e 5d 89 10 5b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

