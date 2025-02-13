rule Trojan_Win32_Ymacco_YAA_2147905812_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ymacco.YAA!MTB"
        threat_id = "2147905812"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ymacco"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 04 24 c6 00 ea 2d e3 39 46 00 05 6a 3a 46 00}  //weight: 2, accuracy: High
        $x_10_2 = {80 30 73 8b 04 24 89 c6 66 ad 89 f2 58 ff 70 fb 8f 02 b9 ?? ?? ?? ?? 81 e9 ?? ?? ?? ?? 8d 34 08 b9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ymacco_NIT_2147928820_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ymacco.NIT!MTB"
        threat_id = "2147928820"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ymacco"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {42 89 d0 40 8b 04 85 30 5f 41 00 25 ff ff ff 7f 8b 1c 95 30 5f 41 00 81 e3 00 00 00 80 09 d8 89 c1 89 d0 05 8d 01 00 00 89 cb d1 eb 8b 34 85 30 5f 41 00 31 de 89 c8 83 e0 01 8b 04 85 20 17 41 00 31 c6 89 34 95 30 5f 41 00 81 fa e2 00 00 00 7c ae}  //weight: 2, accuracy: High
        $x_2_2 = {42 89 d0 48 8b 0c 85 30 5f 41 00 89 c8 c1 e8 1e 31 c8 69 c0 65 89 07 6c 01 d0 89 04 95 30 5f 41 00 81 fa 6f 02 00 00 7c d7}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

