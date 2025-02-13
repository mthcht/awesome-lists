rule Trojan_Win32_Fariet_Inj_2147788935_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fariet.Inj!MTB"
        threat_id = "2147788935"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fariet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 07 09 c0 74 3c 8b 5f 04 8d 84 30 3c 93 0a 00 01 f3 50 83 c7 08 ff 96 dc 93 0a 00 95 8a 07 47 08 c0 74 dc}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 f0 89 45 ec 8b 45 fc 03 45 ec 73 05 e8 a9 43 f9 ff c6 00 b7 ff 45 f0 ff 4d e8 75 e2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Fariet_KR_2147793435_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fariet.KR!MTB"
        threat_id = "2147793435"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fariet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 33 d2 89 ?? ?? ?? ?? 00 33 c0 a3 88 bb 46 00 e8 f6 32}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

