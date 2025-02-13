rule Trojan_Win64_Tasker_CI_2147839270_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tasker.CI!MTB"
        threat_id = "2147839270"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tasker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 06 eb 02 38 64 44 8b 5e 04 eb ?? ?? 41 b8 ?? ?? ?? ?? eb ?? ?? ?? 41 bc ?? ?? ?? ?? eb ?? ?? ?? 4c 8b 36 eb ?? ?? 41 81 f4 ?? ?? ?? ?? 71}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tasker_KAA_2147900006_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tasker.KAA!MTB"
        threat_id = "2147900006"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tasker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {49 89 f3 41 8b 03 49 ba ?? ?? ?? ?? ?? ?? ?? ?? 48 8d 76 18 48 83 ee 14 eb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

