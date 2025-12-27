rule Trojan_Win64_Phave_MR_2147947780_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Phave.MR!MTB"
        threat_id = "2147947780"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Phave"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 89 c1 48 8b 05 ?? ?? 00 00 ff d0 48 89 85 ?? ?? 00 00 48 83 bd ?? ?? 00 00 00 75 0a b8 01 00 00 00 e9 ?? ?? 00 00 48 8b 85 ?? ?? 00 00 48 8d 15 ?? ?? 00 00 48 89 c1 48 8b 05 ?? ?? 00 00 ff d0}  //weight: 5, accuracy: Low
        $x_10_2 = {48 01 d0 0f b6 00 48 8b 8d ?? ?? 00 00 48 8b 95 ?? ?? 00 00 48 01 ca 32 85 ?? ?? 00 00 88 02 48 83 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Phave_GVA_2147947902_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Phave.GVA!MTB"
        threat_id = "2147947902"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Phave"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 01 d0 0f b6 00 32 85 be 11 00 00 48 8b 8d c8 11 00 00 48 8b 95 18 12 00 00 48 01 ca 32 85 bf 11 00 00 88 02 48 83 85 18 12 00 00 01 48 8b 85 18 12 00 00 48 3b 85 10 12 00 00 72 b5}  //weight: 2, accuracy: High
        $x_2_2 = {48 01 d0 0f b6 00 48 8b 8d b8 11 00 00 48 8b 95 f8 11 00 00 48 01 ca 32 85 af 11 00 00 88 02 48 83 85 f8 11 00 00 01 48 8b 85 f8 11 00 00 48 3b 85 f0 11 00 00 72 bb}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Phave_GVB_2147947903_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Phave.GVB!MTB"
        threat_id = "2147947903"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Phave"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 89 e5 89 d0 89 ca 88 55 10 88 45 18 0f b6 45 10 32 45 18}  //weight: 2, accuracy: High
        $x_1_2 = {88 03 48 83 85 18 12 00 00 01 48 8b 85 18 12 00 00 48 3b 85 10 12 00 00 72 af}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

