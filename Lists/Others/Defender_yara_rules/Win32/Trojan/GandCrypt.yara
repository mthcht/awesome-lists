rule Trojan_Win32_GandCrypt_GA_2147744723_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GandCrypt.GA!MTB"
        threat_id = "2147744723"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c7 c1 e8 05 03 44 24 18 8b cf c1 e1 04 03 4c 24 1c 8d 14 3b 33 c1 33 c2 2b f0 8b c6 c1 e8 05 03 44 24 20 8b ce c1 e1 04 03 4c 24 24 8d 14 33 33 c1 33 c2 45 2b f8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GandCrypt_KMG_2147745171_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GandCrypt.KMG!MTB"
        threat_id = "2147745171"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 e0 04 03 45 e4 8b 4d f8 03 4d f4 33 c1 8b 55 f8 c1 ea 05 03 55 e0 33 c2 8b 4d fc 2b c8 89 4d fc 8b 55 dc 83 ea 01 8b 45 f4 2b c2 89 45 f4 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GandCrypt_G_2147745172_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GandCrypt.G!MTB"
        threat_id = "2147745172"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 8a 94 01 32 09 00 00 8b 4d 08 88 14 01 5d}  //weight: 1, accuracy: High
        $x_1_2 = {8d 9b 00 00 00 00 8b 7d fc 8a 44 37 03 8a d0 8a d8 80 e2 fc 24 f0 c0 e2 04 0a 54 37 01 8b 7d fc 02 c0 c0 e3 06 0a 5c 37 02 02 c0 0a 04 37 8b 7d f8 88 04 39 41 88 14 39 41 88 1c 39 83 c6 04 41 3b 75 f4 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GandCrypt_GS_2147745173_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GandCrypt.GS!MTB"
        threat_id = "2147745173"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 f5 d0 00 00 01 45 fc 8b 45 fc 8a 04 38 8b 0d ?? ?? ?? ?? 88 04 39 a1 ?? ?? ?? ?? 47 3b f8 72 c7 8d 4d f4 51 6a 40 50 ff 35}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 81 ec 20 08 00 00 a1 ?? ?? ?? ?? 33 c5 89 45 fc 56 57 33 ff 81 3d ?? ?? ?? ?? 12 0f 00 00 75 ?? 57 8d 85 e0 f7 ff ff 50 57}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GandCrypt_GB_2147745308_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GandCrypt.GB!MTB"
        threat_id = "2147745308"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 fe 70 d2 14 00 7e ?? 81 bd 6c ff ff ff 28 9b 1a 75 74 ?? 81 7d ?? ?? 2a 69 12 75 ?? 46 81 fe 01 3f 14 22 7c ?? a1 ?? ?? ?? ?? 8b f7 05 3b 2d 0b 00 a3 ?? ?? ?? ?? 81 fe 89 62 65 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GandCrypt_GE_2147745459_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GandCrypt.GE!MTB"
        threat_id = "2147745459"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 ff 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 69 c0 fd 43 03 00 56 a3 ?? ?? ?? ?? 81 05 ?? ?? ?? ?? c3 9e 26 00 81 3d ?? ?? ?? ?? a5 02 00 00 8b 35 ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {50 6a 00 ff d7 81 fe 4a 38 02 00 7e ?? b9 db 86 00 00 66 3b d9 75 ?? 46 81 fe 36 9c 97 01 7c}  //weight: 1, accuracy: Low
        $x_1_3 = {33 f6 85 ff 7e ?? 53 81 ff 69 04 00 00 75 ?? 6a 00 ff 15 ?? ?? ?? ?? 6a 00 6a 00 6a 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_4 = {30 04 1e 46 3b f7 7c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_GandCrypt_GD_2147746244_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GandCrypt.GD!MTB"
        threat_id = "2147746244"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 6a 00 ff d7 81 fe 4a 38 02 00 7e ?? b9 db 86 00 00 66 3b d9 75 ?? 46 81 fe 36 9c 97 01 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 ff 15 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 69 c9 ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 81 05 ?? ?? ?? ?? c3 9e 26 00 81 3d ?? ?? ?? ?? cf 12 00 00 0f b7 1d ?? ?? ?? ?? 75 ?? 6a 00 6a 00 ff 15 ?? ?? ?? ?? 8b 45 f8 30 1c 06 46 3b f7 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GandCrypt_AR_2147747899_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GandCrypt.AR!MTB"
        threat_id = "2147747899"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 c9 fd 43 03 00 89 0d ?? ?? ?? 00 81 05 ?? ?? ?? 00 c3 9e 26 00 81 3d ?? ?? ?? 00 cf 12 00 00 0f b7 1d ?? ?? ?? 00 75 ?? 6a 00 6a 00 ff 15 ?? ?? ?? ?? 8b 45 f8 30 1c 06 45 00 ff 15 ?? ?? ?? ?? 8b 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GandCrypt_GH_2147748116_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GandCrypt.GH!MTB"
        threat_id = "2147748116"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 ff 15 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 69 d2 fd 43 03 00 89 15 ?? ?? ?? ?? 81 05 ?? ?? ?? ?? c3 9e 26 00 a0 ?? ?? ?? ?? 30 04 1e 46 3b f7 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 4a 38 02 00 7e ?? ba db 86 00 00 66 3b ca 75 ?? 40 3d 59 68 00 00 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GandCrypt_GG_2147748554_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GandCrypt.GG!MTB"
        threat_id = "2147748554"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 5f 33 00 00 85 c0 74 ?? 8b 4d f8 3b 0d ?? ?? ?? ?? 72 ?? eb ?? 8b 75 f8 03 75 f0 68 50 11 00 00 ff 15 ?? ?? ?? ?? 03 f0 8b 55 f8 03 55 f0 8b 45 fc 8b 4d f4 8a 0c 31 88 0c 10 8b 55 f8 83 c2 01 89 55 f8 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GandCrypt_GI_2147748555_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GandCrypt.GI!MTB"
        threat_id = "2147748555"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 d8 c7 05 ?? ?? ?? ?? 2e ce 50 91 a1 ?? ?? ?? ?? 81 fa a9 0f 00 00 89 5c 24 18 bb 40 2e eb ed 0f 44 c3 8b df c1 eb 05 03 d9 a3 ?? ?? ?? ?? 8d 04 3e 81 fa 76 09 00 00 75 ?? 33 c9 8d 84 24 ?? ?? ?? ?? 51 51 50 51}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GandCrypt_GJ_2147748560_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GandCrypt.GJ!MTB"
        threat_id = "2147748560"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 81 ec 10 08 00 00 a1 ?? ?? ?? ?? 33 c5 89 45 f8 89 95 f0 f7 ff ff 89 8d f4 f7 ff ff 81 3d ?? ?? ?? ?? a3 09 00 00 75 ?? 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 51 a1 ?? ?? ?? ?? 69 c0 fd 43 03 00 a3 ?? ?? ?? ?? 81 05 ?? ?? ?? ?? c3 9e 26 00 8b 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GandCrypt_DSK_2147749128_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GandCrypt.DSK!MTB"
        threat_id = "2147749128"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 4c 24 70 8b 54 24 30 89 35 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 8b f7 c1 ee 05 03 74 24 78 03 d9 03 d7 33 da 81 3d ?? ?? ?? ?? 72 07 00 00 75}  //weight: 2, accuracy: Low
        $x_2_2 = {0f b6 c8 56 89 0d ?? ?? ?? ?? 0f b6 81 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 0f b6 f0 89 35 ?? ?? ?? ?? 81 f9 66 0d 00 00 73}  //weight: 2, accuracy: Low
        $x_2_3 = {8b f0 8b c1 33 d2 f7 f6 41 8a 04 1a 30 44 39 ff 3b 4d 08 72}  //weight: 2, accuracy: High
        $x_2_4 = {8b 4d fc 8d 94 01 bc 01 00 00 8b 45 08 89 10 8b 4d 08 8b 11 81 ea bc 01 00 00 8b 45 08 89 10}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_GandCrypt_GF_2147749287_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GandCrypt.GF!MTB"
        threat_id = "2147749287"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 4d e0 81 7d e0 4e ce 21 00 7d ?? 81 7d e0 e8 a7 03 00 75 ?? 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? a3 ?? ?? ?? ?? 81 3d ?? ?? ?? ?? 0b 12 00 00 75 ?? 8d 95 9c f3 ff ff 52 6a 00 ff 15 ?? ?? ?? ?? eb ?? 8b e5 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GandCrypt_PVD_2147750606_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GandCrypt.PVD!MTB"
        threat_id = "2147750606"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 d0 89 15 ?? ?? ?? ?? 81 f9 66 0d 00 00 73 0d 00 0f b6 81 ?? ?? ?? ?? 03 05}  //weight: 1, accuracy: Low
        $x_1_2 = {30 04 2e 83 ee 01 79 05 00 e8}  //weight: 1, accuracy: Low
        $x_2_3 = {8b ce 8b c6 c1 e1 04 03 0d ?? ?? ?? ?? c1 e8 05 03 05 ?? ?? ?? ?? 33 c8 8d 04 37 2b 7d fc}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_GandCrypt_PVS_2147752582_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GandCrypt.PVS!MTB"
        threat_id = "2147752582"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f be 19 e8 ?? ?? ?? ?? 33 d8 8b 55 c4 03 55 fc 88 1a eb}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GandCrypt_PVR_2147753594_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GandCrypt.PVR!MTB"
        threat_id = "2147753594"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {69 c9 fd 43 03 00 6a 00 81 c1 c3 9e 26 00 6a 00 89 0d ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8a 15 ?? ?? ?? ?? 30 14 3e 46 3b f3 7c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GandCrypt_KSV_2147753654_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GandCrypt.KSV!MTB"
        threat_id = "2147753654"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {69 c0 fd 43 03 00 53 05 c3 9e 26 00 53 a3 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? a0 ?? ?? ?? ?? 30 04 3e 46 3b 75 08 7c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GandCrypt_PVP_2147753659_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GandCrypt.PVP!MTB"
        threat_id = "2147753659"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {69 c0 fd 43 03 00 8d 8d ?? ?? ff ff 51 05 c3 9e 26 00 68 ?? ?? ?? ?? a3 05 00 a1}  //weight: 2, accuracy: Low
        $x_1_2 = {46 3b f3 7c 08 00 e8 ?? ff ff ff 30 04}  //weight: 1, accuracy: Low
        $x_2_3 = {69 c0 fd 43 03 00 05 c3 9e 26 00 a3 ?? ?? ?? ?? c1 e8 10 25 ff 7f 00 00 c3 05 00 a1}  //weight: 2, accuracy: Low
        $x_1_4 = {6a 00 ff 15 08 00 e8 ?? ff ff ff 30 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_GandCrypt_PVC_2147753715_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GandCrypt.PVC!MTB"
        threat_id = "2147753715"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 cb 03 f1 5b 3d 97 0d 00 00 73 13 00 8b 0d ?? ?? ?? ?? 88 98 ?? ?? ?? ?? 0f b6 b1}  //weight: 2, accuracy: Low
        $x_2_2 = {30 04 37 4e 79 05 00 e8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_GandCrypt_PVE_2147754080_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GandCrypt.PVE!MTB"
        threat_id = "2147754080"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 00 ff 15 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 30 04 37 8d 85 fc f7 ff ff 50 6a 00 ff 15 ?? ?? ?? ?? 46 3b 75 08 7c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GandCrypt_PVF_2147754184_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GandCrypt.PVF!MTB"
        threat_id = "2147754184"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 e0 8b 5d d4 89 38 8b 45 dc 89 30 8b 45 f8 40 89 45 f8 3b 45 d8 0f 82 ?? ?? ?? ?? 5f 5e 5b 8b e5 5d c3}  //weight: 2, accuracy: Low
        $x_2_2 = {8b c3 c1 e9 05 03 4d f0 c1 e0 04 03 45 ec 33 c8 8d 04 1e 33 c8 8d b6 ?? ?? ?? ?? 2b f9 83 6d fc 01 75 ?? 8b 75 e8 89 3e 5f 89 5e 04 5e 5b 8b e5 5d c3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_GandCrypt_PVG_2147754185_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GandCrypt.PVG!MTB"
        threat_id = "2147754185"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {69 c0 fd 43 03 00 57 05 c3 9e 26 00 57 a3 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? a0 ?? ?? ?? ?? 30 04 1e 46 3b 75 08 7c}  //weight: 2, accuracy: Low
        $x_1_2 = {56 8b 45 08 8d 34 07 e8 ?? ?? ?? ?? 30 06 47 3b 7d 0c 7c ?? 5e}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 4d fc 33 cd 25 ff 7f 00 00 e8 ?? ?? ?? ?? c9 c3 07 00 0f b7 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_GandCrypt_PVH_2147754194_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GandCrypt.PVH!MTB"
        threat_id = "2147754194"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 4d f4 03 4d f0 33 c1 8b 55 f4 c1 ea 05 03 55 e0 33 c2 8b 4d dc 2b c8 89 4d dc 8b 55 f0 2b 55 e4 89 55 f0 eb ?? 8b 45 d8 8b 4d dc 89 08 8b 55 d8 8b 45 f4 89 42 04}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 4d f8 c1 e9 05 8b 55 0c 03 4a 04 33 c1 8b 4d e4 2b c8 89 4d e4 ff 75 f0 e8 ?? ?? ?? ?? 89 45 f0 eb ?? 8b 45 08 8b 4d e4 89 08 8b 45 08 8b 4d f8 89 48 04}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_GandCrypt_PVI_2147754411_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GandCrypt.PVI!MTB"
        threat_id = "2147754411"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b d6 c1 ea 05 03 54 24 10 8b c6 c1 e0 04 03 44 24 14 8d 0c 33 33 d0 33 d1 2b fa 81 fd 8b 02 00 00 73}  //weight: 2, accuracy: High
        $x_2_2 = {8b 55 f4 c1 ea 05 03 55 e0 33 c2 8b 4d dc 2b c8 89 4d dc 81 7d fc c5 22 00 00 73}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_GandCrypt_PVB_2147755851_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GandCrypt.PVB!MTB"
        threat_id = "2147755851"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 5c 24 1c 89 33 8b 74 24 18 89 7b 04 81 fe 13 e6 33 00 76}  //weight: 1, accuracy: High
        $x_1_2 = {89 74 24 18 89 5c 24 1c 3b 74 24 2c 0f 82 ?? ?? ?? ?? 5e 5d 5b 8b 4c 24 44 5f 33 cc e8 ?? ?? ?? ?? 83 c4 44 c2 0c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GandCrypt_PVJ_2147756252_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GandCrypt.PVJ!MTB"
        threat_id = "2147756252"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b ce c1 e9 05 03 0d ?? ?? ?? ?? 50 33 d1 8d 0c 30 33 d1 2b fa e8 ?? ?? ?? ?? 4b 75 ?? 8b 44 24 1c 89 38 5f 89 70 04 5e 5d 5b 83 c4 08 c2 04 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GandCrypt_DSA_2147757713_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GandCrypt.DSA!MTB"
        threat_id = "2147757713"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f0 03 45 e4 89 45 d8 8b 45 f0 c1 e8 05 89 45 f8 c7 05 ?? ?? ?? ?? 2e ce 50 91 8b 45 f8 03 45 cc 89 45 f8 81 3d ?? ?? ?? ?? 76 09 00 00 75 0a 00 c7 05 ?? ?? ?? ?? 40 2e eb ed}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GandCrypt_DSB_2147759841_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GandCrypt.DSB!MTB"
        threat_id = "2147759841"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 41 03 8a d0 8a d8 24 f0 80 e2 fc c0 e0 02 0a 01 c0 e2 04 0a 51 01 c0 e3 06 0a 59 02 88 04 3e 46 88 14 3e 46 88 1c 3e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GandCrypt_DSC_2147763498_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GandCrypt.DSC!MTB"
        threat_id = "2147763498"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 c0 fd 43 03 00 6a 00 05 c3 9e 26 00 6a 00 a3 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? a0 ?? ?? ?? ?? 30 04 3e 46 3b f3 7c 05 00 a1}  //weight: 1, accuracy: Low
        $x_1_2 = "De bemojeyuze bazobupuyobumetelawefibu diwuza hibeligacakujakaco" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GandCrypt_RF_2147788213_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GandCrypt.RF!MTB"
        threat_id = "2147788213"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c1 8b 0d ?? ?? ?? ?? 89 44 24 ?? 89 4c 24 ?? 8b 30 a1 ?? ?? ?? ?? 89 44 24 ?? a1 ?? ?? ?? ?? 89 44 24 ?? a1 ?? ?? ?? ?? c7 44 24 ?? ba 79 37 9e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

