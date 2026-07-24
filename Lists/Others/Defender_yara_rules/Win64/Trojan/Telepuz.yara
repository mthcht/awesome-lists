rule Trojan_Win64_Telepuz_ATE_2147974414_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Telepuz.ATE!MTB"
        threat_id = "2147974414"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Telepuz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 8d 43 01 44 0f b6 d8 42 0f b6 4c 1c 10 8d 04 0b 0f b6 d8 8a 44 1c 10 42 88 44 1c 10 88 4c 1c 10}  //weight: 1, accuracy: High
        $x_2_2 = {41 8b c1 83 e0 0f 41 ff c1 0f b6 14 ?? 03 d3 41 03 d0 0f b6 da 8a 44 1c ?? 41 88 03 49 ff c3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

