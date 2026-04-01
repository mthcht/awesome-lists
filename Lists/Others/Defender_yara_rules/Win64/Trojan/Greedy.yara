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

rule Trojan_Win64_Greedy_MX_2147966100_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Greedy.MX!MTB"
        threat_id = "2147966100"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Greedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {45 32 f6 48 8b 4c 24 68 48 85 c9 74 41 48 8b 54 24 78 48 2b d1 48 8b c1}  //weight: 1, accuracy: High
        $x_1_2 = "powershell.exe -Command Compress-Archive -Path" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

