rule Trojan_Win64_TerraCrypt_AB_2147848796_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/TerraCrypt.AB!MTB"
        threat_id = "2147848796"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "TerraCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 83 ec 08 48 c7 04 24 00 00 00 00 48 ff c8 75 ?? 48 83 ec 28 48 8d 15 ?? ?? ?? ?? 48 8d 4c 24 50 e8 ?? ?? ?? ?? 48 8d 15 ?? ?? ?? ?? 48 8d 4c 24 58 e8 ?? ?? ?? ?? 48 8d 15 ?? ?? ?? ?? 48 8d 4c 24 60 e8 ?? ?? ?? ?? 48 8d 15 ?? ?? ?? ?? 48 8d 4c 24 68 e8 ?? ?? ?? ?? 48 8d 15 ?? ?? ?? ?? 48 8d 4c 24 70 e8 ?? ?? ?? ?? c7 44 24 48 00 00 00 00 eb 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_TerraCrypt_AC_2147848797_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/TerraCrypt.AC!MTB"
        threat_id = "2147848797"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "TerraCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 83 ec 08 48 31 c0 48 89 c0 50 48 c7 c0 00 00 00 08 48 89 c0 50 48 c7 c0 40 00 00 00 48 89 c0 50 48 8d 44 24 78 48 89 c0 50 48 31 c0 48 89 c0 50 48 c7 c0 0e 00 00 00 48 89 c0 50 48 8d 84 24 98 00 00 00 48 89 c0 50 59 5a 41 58 41 59 48 83 ec 20 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

