rule Trojan_Win64_LegionLoader_AHB_2147972215_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LegionLoader.AHB!MTB"
        threat_id = "2147972215"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LegionLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {f6 d0 c0 e8 ?? 41 89 d0 41 f6 d0 41 c0 e8 ?? 41 00 c0 41 8a 4c 3e ?? 89 c8 f6 d0 c0 e8 ?? 45 8a 5c 3e ?? 44 89 db f6 d3 c0 eb ?? 00 c3 44 00 c3 45 8a 4c 3e ?? 44 89 c8 f6 d0}  //weight: 30, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

