rule Trojan_Win32_Vimditator_GNA_2147900451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vimditator.GNA!MTB"
        threat_id = "2147900451"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vimditator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b cd 8b d1 8d 74 24 ?? 8d 7c 18 ?? 6a 0a c1 e9 ?? f3 a5 8b ca 83 e1 ?? f3 a4 8b 7b ?? 8b 35 ?? ?? ?? ?? 03 fd 89 7b ?? ff d6 6a 0a ff d6 6a 0a ff d6 81 7b ?? 78 da 04 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

