rule Trojan_Win64_Karstorat_AKR_2147964562_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Karstorat.AKR!MTB"
        threat_id = "2147964562"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Karstorat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 c7 44 24 30 1d 00 00 00 48 8d 05 ?? ?? ?? ?? 48 89 44 24 28 48 89 4c 24 20 48 8d 4d ?? ?? ?? ?? ?? ?? c7 44 24 40 03 00 00 00 48 8b d3 48 8d 4d}  //weight: 1, accuracy: Low
        $x_2_2 = "212.227.65.132" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

