rule Trojan_Win64_Greedy_AH_2147964753_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Greedy.AH!MTB"
        threat_id = "2147964753"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Greedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "High"
    strings:
        $x_30_1 = "[ERROR] Failed to create Steal.zip." ascii //weight: 30
        $x_20_2 = "[INFO] tdirs.txt not found. Starting deep folder search..." ascii //weight: 20
        $x_10_3 = "[DONE] Temporary folder removed." ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

