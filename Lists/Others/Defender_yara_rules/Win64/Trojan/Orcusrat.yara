rule Trojan_Win64_Orcusrat_BZ_2147962963_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Orcusrat.BZ!MTB"
        threat_id = "2147962963"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Orcusrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 54 00 00 00 75 08 66 9d 58 e9 ?? ?? ?? ?? 3d 4c 00 00 00 75 08 66 9d 58 e9 ?? ?? ?? ?? 3d 0f 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

