rule Ransom_Win32_AvaddonCrypt_SN_2147758155_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/AvaddonCrypt.SN!MTB"
        threat_id = "2147758155"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "AvaddonCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 4d fc 3b 0d ?? ?? ?? ?? 72 02 eb ?? 8b 15 ?? ?? ?? ?? 03 55 fc a1 ?? ?? ?? ?? 03 45 fc 8a 08 88 0a 8b 55 fc 83 c2 01 89 55 fc eb ?? 8b e5 5d c3}  //weight: 2, accuracy: Low
        $x_2_2 = {55 8b ec 53 8b 25 ?? ?? ?? ?? 58 8b e8 a1 ?? ?? ?? ?? 50 a1 ?? ?? ?? ?? 50 8b 1d ?? ?? ?? ?? ff e3 5b 5d c3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_AvaddonCrypt_SN_2147758155_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/AvaddonCrypt.SN!MTB"
        threat_id = "2147758155"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "AvaddonCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 83 ec ?? c7 45 ?? 00 00 00 00 a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 89 45 ?? 8b 0d ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 89 4d ?? eb 00 8b 55 ?? 89 55 ?? b8 ?? ?? ?? ?? 85 c0 0f 84 ?? ?? ?? ?? eb 00 8b 4d ?? 89 4d ?? 8b 55 ?? 3b 55 ?? 72}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 0c 0a f7 d9 8b 55 ?? 0f b6 04 02 2b c1 8b 4d ?? 03 4d ?? 03 4d ?? 8b 55 ?? 88 04 0a c7 45 f0 ?? ?? ?? ?? 8b 45 ?? 83 c0 01 89 45 ?? e9 ?? ?? ?? ?? 8b e5 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_AvaddonCrypt_SM_2147761091_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/AvaddonCrypt.SM!MTB"
        threat_id = "2147761091"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "AvaddonCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 81 ec ?? ?? ?? ?? eb 00 eb 00 eb 00 c7 05 ?? ?? ?? ?? 00 00 00 00 a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8d 94 01 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 2d ?? ?? ?? ?? a3 ?? ?? ?? ?? 8b c0 8b c0 8b c0 8b c0 8b c0 8b c0 b8 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8b 80 ?? ?? ?? ?? a3}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 83 ec 3c c7 45 ?? 01 00 00 00 c7 45 ?? 01 00 00 00 c7 45 ?? 01 00 00 00 c7 45 ?? 01 00 00 00 c7 45 ?? 01 00 00 00 c7 45 ?? 01 00 00 00 c7 45 ?? 01 00 00 00 c7 45 ?? 01 00 00 00 c7 45 ?? 01 00 00 00 c7 45 ?? 01 00 00 00 c7 45 ?? 01 00 00 00 c7 45 ?? 01 00 00 00 c7 45 ?? 01 00 00 00 c7 45 ?? 01 00 00 00 c7 45 ?? 01 00 00 00 ff 15 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8b 45 ?? 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_AvaddonCrypt_SO_2147761991_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/AvaddonCrypt.SO!MTB"
        threat_id = "2147761991"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "AvaddonCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {55 8b ec 83 ec ?? c7 45 ?? 01 00 00 00 c7 45 ?? 01 00 00 00 c7 45 ?? 01 00 00 00 c7 45 ?? 01 00 00 00 c7 45 ?? 01 00 00 00 c7 45 ?? 01 00 00 00 c7 45 ?? 01 00 00 00 00 02 8b ?? ?? [0-4] ff 15 ?? ?? ?? ?? 8b ?? ?? [0-4] ff 15 ?? ?? ?? ?? 8b ?? ?? [0-4] ff 15 ?? ?? ?? ?? 8b ?? ?? [0-4] ff 15}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

