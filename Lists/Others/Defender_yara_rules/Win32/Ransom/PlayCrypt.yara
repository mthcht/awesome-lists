rule Ransom_Win32_PlayCrypt_PA_2147829131_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/PlayCrypt.PA!MTB"
        threat_id = "2147829131"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "PlayCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c3 02 83 fb 08 7c [0-4] 8b 5d ?? 8b ca 83 e1 07 f6 d0 32 44 0d ?? 88 04 16 42 89 55 ?? 3b 55 ?? 0f 82}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b7 f9 0f af fe c7 45 [0-6] 89 7d ?? 8b 7d ?? 33 db 8b 55 ?? 8b cf 83 e1 07 89 5d ?? 47 89 7d ?? 8a 4c 0d ?? 32 c8 88 0a 42 8b 4d ?? 89 55 ?? 3b 7d ?? 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Ransom_Win32_PlayCrypt_MP_2147831401_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/PlayCrypt.MP!MTB"
        threat_id = "2147831401"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "PlayCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 54 31 03 83 ef 04 0f b6 4c 31 02 c1 e2 08 0b d1 8b 4d fc c1 e2 08 0f b6 4c 31 01 0b d1 8b 4d fc c1 e2 08 0f b6 0c 31 83 c6 04 0b d1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_PlayCrypt_MP_2147831401_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/PlayCrypt.MP!MTB"
        threat_id = "2147831401"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "PlayCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 8b 44 15 f4 66 83 e8 01 b9 02 00 00 00 6b d1 00 66 89 44 15 f4 b8 02 00 00 00 6b c8 00 66 8b 54 0d e4 66 83 c2 01 b8 02 00 00 00 6b c8 00 66 89 54 0d e4 8b 95 ac fd ff ff 83 c2 01 89 95 ac fd ff ff 8b 85 94 fd ff ff 83 c0 01 89 85 94 fd}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 94 89 45 90 8b 4d 20 51 8b 55 1c 52 8b 45 18 50 8b 4d 14 51 8b 55 10 52 8b 45 0c 50 8b 4d 08 51}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_PlayCrypt_MKU_2147936683_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/PlayCrypt.MKU!MTB"
        threat_id = "2147936683"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "PlayCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6b d1 07 0f b6 44 15 e0 03 85 e0 fe ff ff 2b 85 e8 fe ff ff b9 02 00 00 00 6b d1 03 66 89 84 15 ?? ?? ff ff b8 01 00 00 00 d1 e0 0f b6 4c 05 e0 ba 01 00 00 00 6b c2 00 88 4c 05 e0 8b 8d 98 fe ff ff 3b 8d 9c fe ff ff 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

