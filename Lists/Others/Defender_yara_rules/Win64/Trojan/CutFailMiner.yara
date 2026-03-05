rule Trojan_Win64_CutFailMiner_YBE_2147964118_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CutFailMiner.YBE!MTB"
        threat_id = "2147964118"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CutFailMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 c0 66 89 41 04 0f b6 c2 32 41 06 34 7a 0f b6 c0 66 89 41 06 0f b6 c2 32 41 ?? 34 b7 0f b6 c0 66 89}  //weight: 2, accuracy: Low
        $x_2_2 = {40 32 f9 80 c1 ?? 40 0f b6 c7 66 89 44 54 42 32 4c 24 40 32 4c 54 44 0f b6 c1 66 89 44 54}  //weight: 2, accuracy: Low
        $x_1_3 = "IdllEntry" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

