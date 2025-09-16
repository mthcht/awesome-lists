rule Trojan_Win64_Xworm_PGXS_2147948876_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Xworm.PGXS!MTB"
        threat_id = "2147948876"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Xworm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {c6 84 24 31 5a 00 00 68 c6 84 24 32 5a 00 00 43 c6 84 24 33 5a 00 00 33 c6 84 24 34 5a 00 00 34 c6 84 24 35 5a 00 00 68 c6 84 24 36 5a 00 00 78 c6 84 24 37 5a 00 00 51 c6 84 24 38 5a 00 00 72 c6 84 24 39 5a 00 00 4b c6 84 24 3a 5a 00 00 58 c6 84 24 3b 5a 00 00 34}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Xworm_AXW_2147952319_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Xworm.AXW!MTB"
        threat_id = "2147952319"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Xworm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 8b da 8b f9 48 8d 0d 02 71 03 00 ff 15 ?? ?? ?? ?? 48 8d 15 8d 5d 03 00 48 8b c8 ff 15 ?? ?? ?? ?? 48 85 c0 48 0f 44 05 91 92 03 00 48 8b d3 8b cf}  //weight: 2, accuracy: Low
        $x_3_2 = {48 8d 0d 9b 61 03 00 ff 15 ?? ?? ?? ?? 48 8b c8 48 8d 15 eb 4d 03 00 48 8b d8 ff 15 ?? ?? ?? ?? 48 8d 15 83 4a 03 00 48 8b cb 48 89 05 89 1b 04 00 ff 15 ?? ?? ?? ?? 48 8d 15 fc 4d 03 00 48 8b cb 48 89 05 7a 1b 04 00 ff 15}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

