rule Trojan_Win32_Kelihos_AKI_2147958028_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kelihos.AKI!MTB"
        threat_id = "2147958028"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kelihos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c0 40 8a cb d3 e0 8b 4d e8 85 c1 74 5a 8a c3 04 61 c7 45 ec 20 3a 5c 00 88 45 ec 8d 45 ec 50}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Kelihos_AKS_2147958045_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kelihos.AKS!MTB"
        threat_id = "2147958045"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kelihos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 b0 33 40 00 57 ff d6 68 bc 33 40 00 57 a3 ?? ?? ?? ?? ff d6 68 cc 33 40 00 57 a3 ?? ?? ?? ?? ff d6 68 d8 33 40 00 57 a3 ?? ?? ?? ?? ff d6 68 e0 33 40 00 57}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

