rule Trojan_Win64_Dodek_PAFH_2147918102_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dodek.PAFH!MTB"
        threat_id = "2147918102"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dodek"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {49 bb ed 5b e1 81 b1 ad d3 7f 66 ?? 43 8d ?? ?? 80 e1 07 c0 e1 03 49 8b d3 48 d3 ea 41 30 50 ff 41 0f b6 c8 41 2a c9 80 e1 07 c0 e1 03 49 8b d3 48 d3 ea 41 30 10 49 83 c0 02 4b 8d ?? ?? 48 83 f8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

