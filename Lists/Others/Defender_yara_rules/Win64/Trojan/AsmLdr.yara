rule Trojan_Win64_AsmLdr_C_2147982553_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AsmLdr.C!MTB"
        threat_id = "2147982553"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AsmLdr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 04 11 83 f0 ?? 66 89 44 54 ?? 48 ff c2 49 39 d0 75}  //weight: 10, accuracy: Low
        $x_10_2 = {46 8a 14 09 45 30 c2 45 0f b6 d2 66 46 89 14 48 49 ff c1 4c 39 ca 75}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

