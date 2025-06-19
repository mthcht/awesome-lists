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

rule Trojan_Win64_Tasker_KK_2147944058_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tasker.KK!MTB"
        threat_id = "2147944058"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tasker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {b9 01 00 00 00 f0 48 0f c1 0d ?? ?? 16 00 49 89 cf 4d 31 c7 4c 89 fb 48 c1 c3 10 4f 8d 24 0f 4c 31 e3 4e 8d 2c 13 4c 31 e9 4d 01 df 4d 89 fc 49 c1 c4 20 48 c1 c3 15 4d 31 f7}  //weight: 10, accuracy: Low
        $x_5_2 = {48 89 44 24 30 48 8d 84 24 78 01 00 00 ?? ?? ?? 24 20 48 c7 44 24 38 00 00 00 00 c7 44 24 28 0c 00 00 00 48 89 f1 ba 00 14 2d 00 4c 8d 84 24 b4 01 00 00 41 b9 0c 00 00 00 e8}  //weight: 5, accuracy: Low
        $x_7_3 = "cmd/Cschtasks/Create/SCONLOGON/TN/TR/RLHIGHEST/F" ascii //weight: 7
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

