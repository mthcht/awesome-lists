rule Trojan_Win32_Draftor_GVA_2147976397_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Draftor.GVA!MTB"
        threat_id = "2147976397"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Draftor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 10 8b 45 f0 83 e0 3f 0f b6 80 [0-4] 31 c2 8b 45 f0 05 [0-4] 88 10 83 45 f0 01 a1 [0-4] 39 45 f0 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Draftor_A_2147977532_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Draftor.A!MTB"
        threat_id = "2147977532"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Draftor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {c1 e1 08 81 e2 38 73 c8 9e 83 e6 c7 81 f1 38 73 c8 9e 09 f2 31 d1}  //weight: 6, accuracy: High
        $x_4_2 = {c7 44 24 14 00 00 00 00 8a 54 24 1b b8 7a e9 ec 05 b9 3c aa 53 78 f6 c2 01 0f 45 c1 89 44 24 10}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

