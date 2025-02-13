rule Ransom_Win64_DagonLocker_RPX_2147893539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/DagonLocker.RPX!MTB"
        threat_id = "2147893539"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "DagonLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 4b 38 44 8b 4b 04 33 c9 8b 53 38 45 8b c1 44 33 83 88 00 00 00 44 33 8b 04 01 00 00 41 81 e8 ?? ?? ?? ?? 41 81 e9 ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_DagonLocker_RPY_2147893540_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/DagonLocker.RPY!MTB"
        threat_id = "2147893540"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "DagonLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4c 8b d0 48 85 c0 74 4c 48 8b 84 24 50 01 00 00 4c 8b ce 48 89 44 24 40 4c 8b c5 8b 84 24 48 01 00 00 41 8b d6 89 44 24 38 49 8b cf 48 8b 84 24 40 01 00 00 48 89 44 24 30 8b 84 24 38 01 00 00 89 44 24 28 8b 84 24 30 01 00 00 89 44 24 20 41 ff d2 8b d8 48 8b cf ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

