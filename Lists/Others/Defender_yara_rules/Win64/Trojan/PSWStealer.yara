rule Trojan_Win64_PSWStealer_GNN_2147813279_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PSWStealer.GNN!MTB"
        threat_id = "2147813279"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PSWStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 8b 05 82 d6 07 00 48 33 c4 48 89 84 24 ?? ?? ?? ?? 45 8b d9 45 0f b6 d0 48 8b 01 48 83 7a 10 00 75 2b 44 0f b6 8c 24 ?? ?? ?? ?? 45 8b c3 41 0f b6 d2 ff 50 60 48 8b 8c 24 ?? ?? ?? ?? 48 33 cc e8 ?? ?? ?? ?? 48 81 c4 ?? ?? ?? ?? c3}  //weight: 10, accuracy: Low
        $x_1_2 = "hhiuew33.com" ascii //weight: 1
        $x_1_3 = "fj4ghga23_fsa.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_PSWStealer_ARAF_2147975404_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PSWStealer.ARAF!MTB"
        threat_id = "2147975404"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PSWStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {8d 50 ff 83 e2 0e 0f b6 14 0a 30 54 06 ff 89 c2 83 e2 0f 0f b6 14 0a 30 14 06 48 83 c0 02 48 3d 01 20 00 00 75 da}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

