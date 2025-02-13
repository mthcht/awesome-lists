rule Trojan_Win32_Berbew_A_2147895944_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Berbew.A!MTB"
        threat_id = "2147895944"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Berbew"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 a4 65 00 00 f7 e3 89 85 ?? ?? ?? ?? 89 c3 81 f3 18 2d 00 00 81 f3 a6 21 00 00 89 d8 29 d8 89 c3 6a 01 8d 85 ?? ?? ?? ?? 50 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {81 eb 16 45 00 00 81 eb 64 20 00 00 81 f3 7c 27 00 00 81 eb 92 69 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Berbew_AB_2147895945_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Berbew.AB!MTB"
        threat_id = "2147895945"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Berbew"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {bb 9b 3a f9 1f 89 d8 29 d8 89 c3 81 eb e9 27 00 00 b8 42 54 00 00 f7 e3}  //weight: 1, accuracy: High
        $x_1_2 = {81 f3 b9 27 00 00 81 c3 7a 44 00 00 89 d8 29 d8 89 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Berbew_RPY_2147898900_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Berbew.RPY!MTB"
        threat_id = "2147898900"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Berbew"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 45 f8 8b 45 f4 8b 00 89 45 fc 89 d9 31 d9 89 cb 83 c0 44 8b 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

