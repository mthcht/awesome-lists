rule Ransom_Win64_Babuk_SR_2147850295_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Babuk.SR!MTB"
        threat_id = "2147850295"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Babuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 33 c9 48 89 46 ?? 44 8b c7 8b d7 33 c9 ff 15 ?? ?? ?? ?? 45 33 c9 44 8b c7 33 d2 48 89 06 33 c9 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Babuk_GZZ_2147945262_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Babuk.GZZ!MTB"
        threat_id = "2147945262"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Babuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {66 83 71 02 6b 66 83 71 04 3f 66 83 71 0a 49 66 83 71 10 0b 66 83 71 12 6b 66 83 71 14 3f 66 83 71 1a 49 66 83 71 20 0b 66 83 71 22 6b 66 83 71 24 3f c6 41 26 00 48 8b c1}  //weight: 10, accuracy: High
        $x_1_2 = "critical points of your network has been compromised" ascii //weight: 1
        $x_1_3 = "all of your company's critical data has been transferred to our servers" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

