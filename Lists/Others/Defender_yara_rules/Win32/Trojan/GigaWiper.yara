rule Trojan_Win32_GigaWiper_GVA_2147973610_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GigaWiper.GVA!MTB"
        threat_id = "2147973610"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GigaWiper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 5c 24 21 31 da 88 50 12 0f b6 54 24 26 0f b6 5c 24 39 01 da 88 50 13 0f b6 54 24 2f 0f b6 5c 24 35 01 da 88 50 14}  //weight: 1, accuracy: High
        $x_1_2 = {0f b6 5c 0c 38 31 d3 88 5c 0c 38 41 83 f9 0c 7d 0c 0f b6 54 0c 44 72 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GigaWiper_GVB_2147973612_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GigaWiper.GVB!MTB"
        threat_id = "2147973612"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GigaWiper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e8 32 d0 8b 05 [0-4] d3 e8 32 d0 43 32 14 10 41 88 10 49 ff c1 4d 3b cc 72 c7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

