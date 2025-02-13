rule Trojan_Win32_Emotetcrypt_MG_2147764992_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.MG!MTB"
        threat_id = "2147764992"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 83 ec 08 68 [0-4] 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 81 ec 4c 01 00 00 53 56 57 89 65 f8 c7 45 fc [0-4] 8b 5d 08 b9 3e 00 00 00 33 c0 8d bd [0-4] f3 ab}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 40 68 00 10 00 00 51 6a 00 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {5f 5e 64 89 0d 00 00 00 00 5b 8b e5 5d c2 0c 00}  //weight: 1, accuracy: High
        $x_1_4 = "RtlMoveMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_VB_2147765007_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.VB!MTB"
        threat_id = "2147765007"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 03 c2 0f b6 54 24 ?? 8a 14 32 30 10 3b 4c 24 ?? 89 4c 24 ?? 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_VB_2147765007_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.VB!MTB"
        threat_id = "2147765007"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {55 8b ec 83 ec 08 68 [0-4] 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 81 ec 4c 01 00 00 53 56 57 89 65 f8 c7 45 fc [0-4] 8b 5d 08 b9 3e 00 00 00 33 c0 8d bd [0-4] f3 ab 8d 85 [0-4] 33 ff 50 53 89 bd [0-4] 89 bd [0-4] 89 bd [0-4] 89 bd [0-4] 89 bd [0-4] 89 bd [0-4] e8 [0-4] 85 c0 0f 84 [0-4] 0f bf [0-5] 8b c8 33 d2 d1 e9 c1 e8 08 23 c8 83 e1 01 66 81 [0-5] 4c 01 0f 94 c2 84 ca 0f 84 [0-4] 8d 85 [0-4] 8d 8d [0-4] 50 51 ff 15}  //weight: 10, accuracy: Low
        $x_1_2 = {6a 40 68 00 10 00 00 51 6a 00 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {5f 5e 64 89 0d 00 00 00 00 5b 8b e5 5d c2 0c 00}  //weight: 1, accuracy: High
        $x_2_4 = "RtlMoveMemory" ascii //weight: 2
        $x_2_5 = "VirtualAlloc" ascii //weight: 2
        $x_2_6 = "VirtualProtect" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotetcrypt_VC_2147765252_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.VC!MTB"
        threat_id = "2147765252"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 c2 8a 04 38 30 ?? 8b 45 ?? 8b 5d ?? 3b 75 ?? 7c 23 00 03 ?? ?? ?? ?? ?? ?? 99 f7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_VC_2147765252_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.VC!MTB"
        threat_id = "2147765252"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c2 33 d2 f7 35 [0-4] 03 54 24 [0-2] 8a 04 [0-2] 8b 54 24 [0-2] 02 c3 32 04 [0-2] 45 88 45 ff 8b 44 24 [0-2] 48 89 6c 24 24 89 44 24 10 75 [0-2] 5f 5e 5d 5b 83 c4 0c c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_VD_2147765310_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.VD!MTB"
        threat_id = "2147765310"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 c2 8a 04 38 30 ?? 8b 45 ?? 8b 5d ?? 3b 75 ?? 7c 32 00 03 [0-7] f7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_VD_2147765310_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.VD!MTB"
        threat_id = "2147765310"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ca 0f b6 [0-2] 0f b6 [0-2] 03 c1 89 55 [0-2] 33 d2 f7 35 [0-4] 8b 4d [0-2] 03 55 [0-2] 8a 04 32 02 45 ff 32 04 39 88 07 47 ff 4d 0c 75 [0-2] 5f 5e 5b c9 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_VE_2147765385_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.VE!MTB"
        threat_id = "2147765385"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 0c 11 8b c7 2b 05 ?? ?? ?? ?? 03 45 ?? 30 ?? 47 89 7d ?? 3b 7d ?? 0f 8c 32 00 0f b6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_VE_2147765385_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.VE!MTB"
        threat_id = "2147765385"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c2 33 d2 f7 f1 [0-4] 03 55 [0-2] 8a 04 32 [0-4] 02 45 [0-2] 32 04 [0-2] 88 07 47 ff 4d [0-2] 75 [0-2] 5f 5e 5b c9 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_VF_2147765479_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.VF!MTB"
        threat_id = "2147765479"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 d2 8a 0c ?? 8b 45 ?? 30 ?? 3b 5d ?? 7c 28 00 03 [0-7] f7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_VF_2147765479_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.VF!MTB"
        threat_id = "2147765479"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c2 33 d2 f7 35 [0-4] 03 d5 8a 04 [0-2] 8a 54 [0-2] 02 c2 8b 54 [0-2] 32 04 [0-2] 43 88 43 [0-2] 8b 44 [0-2] 48 89 44 [0-2] 75 [0-2] 5f 5e 5d 5b 83 c4 0c c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_VG_2147765759_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.VG!MTB"
        threat_id = "2147765759"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff d6 53 53 ff d6 8b 45 [0-2] 8a 0c [0-2] 02 4d [0-2] 8b 45 [0-2] 8b 55 [0-2] 32 0c [0-2] 88 08 40 ff 4d [0-2] 89 45 [0-2] 0f 85 [0-4] 5f 5e 5b c9 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_VG_2147765759_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.VG!MTB"
        threat_id = "2147765759"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 4c 24 ?? 8b d5 2b 15 ?? ?? ?? ?? 45 03 c2 8b 15 ?? ?? ?? ?? 8a 0c ?? 30 ?? 3b 6c ?? ?? 0f 8c}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 c2 8a ?? ?? 30 ?? ?? b9 ?? ?? ?? ?? 8b 7d ?? 47 89 7d ?? 3b 7d ?? 7c 32 00 03 [0-15] f7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_VH_2147765869_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.VH!MTB"
        threat_id = "2147765869"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 01 30 07 8b 45 ?? 3b 75 ?? 0f 8c 19 00 0f b6 cb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_VH_2147765869_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.VH!MTB"
        threat_id = "2147765869"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c1 33 d2 f7 f5 [0-25] 8b 44 [0-2] 8b 54 [0-2] 8a 0c [0-2] 32 0c [0-2] 40 83 6c [0-2] 01 88 48 [0-2] 89 44 [0-2] 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_VI_2147765888_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.VI!MTB"
        threat_id = "2147765888"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 01 8b 4d ?? 30 04 ?? 47 8b 4d ?? 5e 3b 7d ?? 0f 8c 1e 00 0f b6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_VI_2147765888_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.VI!MTB"
        threat_id = "2147765888"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b6 fa 8d [0-2] 88 54 [0-2] e8 [0-4] 8b 0d [0-4] 0f b6 [0-2] 0f b6 [0-2] 03 c2 99 bb [0-4] f7 fb 45 0f b6 [0-2] 8a 0c [0-2] 8b 44 [0-2] 30 4c [0-2] 3b 6c [0-2] 7c}  //weight: 5, accuracy: Low
        $x_1_2 = "GetCurrentProcess" ascii //weight: 1
        $x_1_3 = "VirtualAllocExNuma" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_VJ_2147766446_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.VJ!MTB"
        threat_id = "2147766446"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c7 2b 05 [0-4] 47 03 c8 0f b6 c3 8b 1d [0-4] 8a 04 [0-1] 30 01 8b 4d [0-1] 3b fe}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_VJ_2147766446_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.VJ!MTB"
        threat_id = "2147766446"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c3 99 b9 [0-4] f7 [0-2] 88 [0-50] 8b 55 [0-2] 81 e2 ff 00 00 00 8b 45 [0-2] 03 45 [0-2] 8b 0d [0-4] 8a 00 32 04 11 8b 4d [0-2] 03 4d [0-2] 88 01 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_VK_2147767079_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.VK!MTB"
        threat_id = "2147767079"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff d3 50 ff 15 [0-4] 8b 0d [0-4] 89 08 8b 15 [0-4] 89 50 [0-2] 8a 0d [0-4] 8d 55 [0-2] 52 50 57 88 48 [0-2] ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 06 88 07 8a 46 ?? 88 47 ?? 8a 46 ?? 88 47 ?? 8b 45 ?? 5e 5f c9 c3}  //weight: 1, accuracy: Low
        $x_1_3 = {48 83 c8 fc 40 40 83 f8 [0-2] 7e [0-2] 8b 4d [0-2] 8b 45 [0-2] 51 8d 55 [0-2] 52 56 57 6a 01 57 50 ff 15 [0-4] 85 c0 0f 84 [0-4] ff}  //weight: 1, accuracy: Low
        $x_5_4 = "LdrFindResource_U" ascii //weight: 5
        $x_5_5 = "LdrAccessResource" ascii //weight: 5
        $x_5_6 = "VirtualAllocExNuma" ascii //weight: 5
        $x_5_7 = "CryptEncrypt" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_VK_2147767079_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.VK!MTB"
        threat_id = "2147767079"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Control_RunDLL" ascii //weight: 1
        $x_1_2 = "LdrAccessResource" ascii //weight: 1
        $x_1_3 = "LdrFindResource_U" ascii //weight: 1
        $x_1_4 = "ntdll.dll" ascii //weight: 1
        $x_1_5 = "VirtualAlloc" ascii //weight: 1
        $x_1_6 = "CryptEncrypt" ascii //weight: 1
        $x_1_7 = {68 00 10 00 00 ?? ?? ff ?? 8b ?? ?? ?? 8b ?? ?? ?? 8b ?? 8b ?? c1 ?? ?? 8b ?? f3 ?? 8b ?? 83 ?? ?? f3 a4 8b ?? ?? ?? 8b ?? ?? ?? ?? 8d ?? ?? ?? ?? ?? ?? 6a 01 ?? ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_8 = {83 c4 04 50 [0-8] 68 00 10 00 00 ?? ?? ff ?? 8b ?? ?? ?? 8b ?? 8b ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b ?? ?? ?? 8b ?? ?? ?? 83 ?? ?? ?? 8d ?? ?? ?? ?? ?? ?? 6a 01 ?? ?? ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_VL_2147767249_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.VL!MTB"
        threat_id = "2147767249"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c2 99 b9 [0-4] f7 f9 [0-25] 0f b6 [0-4] a1 [0-4] 8a 0c [0-2] 8b 44 [0-2] 30 0c 28 8b 44 [0-2] 45 3b e8 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_VL_2147767249_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.VL!MTB"
        threat_id = "2147767249"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Control_RunDLL" ascii //weight: 1
        $x_1_2 = "LdrAccessResource" ascii //weight: 1
        $x_1_3 = "LdrFindResource_U" ascii //weight: 1
        $x_1_4 = "ntdll.dll" ascii //weight: 1
        $x_1_5 = "VirtualAlloc" ascii //weight: 1
        $x_1_6 = "CryptEncrypt" ascii //weight: 1
        $x_1_7 = "VirtualProtect" ascii //weight: 1
        $x_1_8 = {8b cf c1 e9 ?? 8b c7 c1 e8 ?? 83 e0 01 83 e1 01 8d 0c 48 8b c7 c1 e8 ?? 8d 04 48 8b 04 85 ?? ?? ?? ?? f7 c7 00 00 00 04 ?? ?? 0d ?? ?? ?? ?? 8d 4d ?? 51 50 56 ff 32 ff 15 ?? ?? ?? ?? f7 d8 1b c0 [0-2] f7 d8 [0-3] c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_VM_2147767331_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.VM!MTB"
        threat_id = "2147767331"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 c2 8a 04 ?? 30 03 8b 45 ?? 8b 5d ?? 3b 75 28 00 03 [0-7] f7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_VM_2147767331_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.VM!MTB"
        threat_id = "2147767331"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c1 99 b9 [0-4] f7 f9 [0-30] 0f b6 [0-4] a1 [0-4] 8a 0c [0-2] 8b 44 [0-2] 30 0c 28 [0-4] 45 3b [0-4] 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_VN_2147767449_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.VN!MTB"
        threat_id = "2147767449"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 54 24 [0-1] a1 [0-4] 8a 0c [0-1] 8b 44 [0-2] 30 0c [0-1] 8b 44 [0-2] [0-1] 3b [0-1] 0f 8c [0-4] 8b [0-3] 8a [0-3] 8a [0-3] 5f 5d 5e 88 [0-1] 88 [0-2] 5b 59 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_VN_2147767449_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.VN!MTB"
        threat_id = "2147767449"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Control_RunDLL" ascii //weight: 1
        $x_1_2 = "LdrAccessResource" ascii //weight: 1
        $x_1_3 = "LdrFindResource_U" ascii //weight: 1
        $x_1_4 = "ntdll.dll" ascii //weight: 1
        $x_1_5 = "VirtualAlloc" ascii //weight: 1
        $x_1_6 = "VirtualProtect" ascii //weight: 1
        $x_1_7 = {8b cf c1 e9 ?? 8b c7 c1 e8 ?? 83 e0 01 83 e1 01 8d 0c 48 8b c7 c1 e8 ?? 8d 04 48 8b 04 85 ?? ?? ?? ?? f7 c7 00 00 00 04 ?? ?? 0d}  //weight: 1, accuracy: Low
        $x_1_8 = {8d 4d 0c 51 50 56 ff 32 ff 15 ?? ?? ?? ?? f7 d8 1b c0 [0-4] f7 d8 [0-3] c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_VO_2147767643_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.VO!MTB"
        threat_id = "2147767643"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 54 24 [0-1] a1 [0-4] 8a 0c [0-1] 8b 44 [0-2] 30 0c [0-6] 3b [0-3] 0f 8c [0-4] 8b [0-3] 8a [0-3] 8a [0-3] 5f [0-2] 88 [0-1] 88 [0-2] 5b 59 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_VP_2147767709_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.VP!MTB"
        threat_id = "2147767709"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 83 ec ?? c7 45 ?? ?? ?? ?? ?? 8b 45 ?? 33 45 ?? 89 45 ?? c7 45 ?? ?? ?? ?? ?? c7 45 ?? ?? ?? ?? ?? c7 45 ?? ?? ?? ?? ?? 8b 4d ?? 83 ?? ?? 0f af 4d ?? 8b 45 ?? 99 f7 f9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_VP_2147767709_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.VP!MTB"
        threat_id = "2147767709"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 54 24 [0-2] 8b 0d [0-4] 8b 44 [0-2] 8a 14 [0-2] 30 14 [0-2] 8b 44 [0-2] 43 3b d8 0f 8c [0-4] 8a [0-4] 8b [0-4] 8a [0-4] 5f [0-2] 88 [0-2] 88 [0-2] 5b 59 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_VQ_2147767768_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.VQ!MTB"
        threat_id = "2147767768"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 54 24 [0-2] 8b 0d [0-4] 8a 14 [0-2] 8b 44 [0-2] 30 14 [0-2] 47 3b [0-4] 0f 8c [0-4] 8a [0-4] 8b [0-4] 8a [0-4] 5e 5d 5b 88 [0-2] 88 [0-2] 5f 83 [0-2] c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_VR_2147767769_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.VR!MTB"
        threat_id = "2147767769"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f2 ae f7 d1 49 [0-2] f7 f1 8a 0c [0-2] 8b 54 [0-2] 8a 04 [0-2] 32 c8 8b 44 [0-2] 46 88 0b 3b f0 75 ?? 5f 5d 5b 5e c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_VS_2147767925_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.VS!MTB"
        threat_id = "2147767925"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 54 24 [0-2] 8b 0d [0-4] 8b 44 [0-4] 8a 14 [0-2] 30 14 [0-2] 8b 44 [0-2] 45 3b [0-2] 7c 87 8b [0-4] 8a [0-4] 5f 88 [0-2] 5b 5e 88 [0-2] 5d 59 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_VT_2147767926_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.VT!MTB"
        threat_id = "2147767926"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 d2 8a [0-2] 8b 44 [0-2] 30 4c [0-2] 3b 74 [0-2] 7c [0-1] 8b [0-3] 8a [0-3] 8a [0-3] 5f 5d 5b 88 [0-1] 88 [0-2] 5e 59}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_VU_2147768394_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.VU!MTB"
        threat_id = "2147768394"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 54 24 [0-2] 8b 0d [0-4] 8b 44 [0-4] 8a 14 [0-2] 30 14 [0-2] 8b 44 [0-2] 45 3b [0-2] 7c ?? 8b [0-4] 8a [0-4] 5f 88 [0-2] 5b 5e 88 [0-2] 5d 59 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_VV_2147768527_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.VV!MTB"
        threat_id = "2147768527"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 c2 8a [0-2] 8b 44 [0-2] 30 14 [0-1] 8b 44 [0-2] 45 3b [0-1] 7c [0-5] 8b [0-3] 8a [0-3] 5f [0-2] 88 [0-1] 88 [0-2] 5d 59 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_VW_2147769057_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.VW!MTB"
        threat_id = "2147769057"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 c2 8b 15 [0-4] 8a 04 10 04 01 01 01 01 31 32 30 33 [0-10] 7c ?? 8a ?? ?? ?? 8b ?? ?? ?? 8a ?? ?? ?? 5f [0-2] 88 [0-2] 88 [0-2] 5d 59 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_VY_2147770330_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.VY!MTB"
        threat_id = "2147770330"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {59 8b d8 8b 0d [0-4] 33 d2 8b c1 f7 f3 03 55 ?? 8a 04 32 8b 55 ?? 32 04 ?? 8b 55 ?? 88 04 ?? ff 05 [0-4] 39 3d [0-4] 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_VY_2147770330_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.VY!MTB"
        threat_id = "2147770330"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 d2 8a ?? ?? 03 01 01 01 30 32 33 ?? ?? 83 ?? ?? ?? 01 75 ?? 8b ?? ?? ?? 8a ?? ?? ?? 8a ?? ?? ?? 5f ?? ?? 88 [0-2] 88 [0-2] 5b 83 ?? ?? c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_VZ_2147771645_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.VZ!MTB"
        threat_id = "2147771645"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 fa 88 54 ?? ?? 0f b6 14 ?? 88 14 ?? 88 04 ?? 0f b6 14 ?? 0f b6 04 ?? 03 c2 99 f7 fb 0f b6 ?? 0f b6 14 ?? 04 01 01 01 01 30 31 32 33 ?? ?? 83 6c ?? ?? 01 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_GI_2147799004_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.GI!MTB"
        threat_id = "2147799004"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 68 00 30 00 00 8b 4d ?? 8b 51 ?? 52 8b 45 ?? 8b 48 ?? 51 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {f3 a4 8b 44 24 0c 5e 5f c3}  //weight: 1, accuracy: High
        $x_1_3 = {83 c4 0c 8b 4d f0 83 c1 28 89 4d f0 eb}  //weight: 1, accuracy: High
        $x_1_4 = {89 45 fc 8b 55 10 52 8b 45 0c 50 8b 4d 08 51 ff 55 fc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_GI_2147799004_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.GI!MTB"
        threat_id = "2147799004"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 68 00 30 00 00 8b ?? ?? 8b ?? ?? ?? 8b ?? ?? 8b ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
        $x_10_2 = {f3 a4 8b 44 24 0c 5e 5f c3}  //weight: 10, accuracy: High
        $x_1_3 = {83 c4 0c 8b ?? ?? 83 ?? 28 89 ?? ?? eb}  //weight: 1, accuracy: Low
        $x_10_4 = {89 45 fc 8b 55 10 52 8b 45 0c 50 8b 4d 08 51 ff 55 fc}  //weight: 10, accuracy: High
        $x_1_5 = "Control_RunDLL" wide //weight: 1
        $x_1_6 = "VirtualAlloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_GI_2147799004_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.GI!MTB"
        threat_id = "2147799004"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 14 2a 03 c2 99 bd ?? ?? ?? ?? f7 fd 8b c1 0f af c3 83 c0 02 0f af c7 83 c0 02 0f af 05 ?? ?? ?? ?? 2b f0 8d 44 1b 02 0f af c3 03 44 24 2c 2b f1 0f af 0d ?? ?? ?? ?? 2b f7 8d 14 72 03 c2 8d 0c 89 0f b6 14 01 8b 44 24 20 30 10}  //weight: 1, accuracy: Low
        $x_1_2 = "!P!8h!at*hdSt<a9Ek@bF6!vuKjnxtd9U+^RFf%I&$H9x^#5nH>_CsGqm5YTx_viE(79Qu+XEO0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_DA_2147799278_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.DA!MTB"
        threat_id = "2147799278"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 68 00 30 00 00 8b 45 ?? 8b 48 ?? 51 8b 55 ?? 8b 42 ?? 50 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {f3 a4 8b 44 24 0c 5e 5f c3}  //weight: 1, accuracy: High
        $x_1_3 = {83 c4 0c 8b 45 e4 83 c0 28 89 45 e4 eb}  //weight: 1, accuracy: High
        $x_1_4 = "Control_RunDLL" ascii //weight: 1
        $x_1_5 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_6 = "RaiseException" ascii //weight: 1
        $x_1_7 = "inflate" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_RF_2147799428_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.RF!MTB"
        threat_id = "2147799428"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 ab aa aa aa f7 e1 8b c3 83 c3 06 c1 ea 03 8d 0c 52 c1 e1 02 2b c1 0f b6 44 85 ?? 30 47 ?? 81 fb 00 34 02 00 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_RMA_2147799583_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.RMA!MTB"
        threat_id = "2147799583"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 e1 0f 0f b6 8c 8d ?? ?? ?? ?? 30 48 ?? 8b 4d ?? 03 c8 83 e1 0f 0f b6 8c 8d ?? ?? ?? ?? 30 48 ?? 83 c0 06 81 fa 00 34 02 00 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_RW_2147805852_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.RW!MTB"
        threat_id = "2147805852"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 30 00 00 8b 45 ?? 50 6a 00 6a ff ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = "6a%trN>GdGr0CaWhvrf#e_fpTvpgE+PU?U4kNJGW?zN?%BAoR8F+" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_RW_2147805852_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.RW!MTB"
        threat_id = "2147805852"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "O0!f?czm?9chhum)if$$ZF06ci*@82<3JI?oKbz^4!PcDupvhakIfbVCzJawebI1jyGyjh*lPbev0s1MkaqhSn<Ad))aaS$x4+?C<ct01*<Zi" ascii //weight: 1
        $x_1_2 = {03 c2 33 d2 f7 35 ?? ?? ?? ?? 8b 44 24 ?? 2b d1 8a 0c 1a 30 08 ff 44 24 ?? 8b 44 24 ?? 3b 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_RWA_2147805853_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.RWA!MTB"
        threat_id = "2147805853"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c1 c1 e9 08 0f b6 c0 33 8c 84 ?? ?? ?? ?? 83 ee 01 75 ?? 8b 5c 24 ?? f6 d1 8b 44 24 ?? 88 0c 03 43 89 5c 24 ?? 81 fb ce 40 00 00 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_RWA_2147805853_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.RWA!MTB"
        threat_id = "2147805853"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Cr6iWeNqbHipZcebsoH2XTvWBfy?9!UpHjmH0t0r1F6iJu(Hz>8+4B!Q9ScpRVgyovLe#x(U7zB00Cmz0>ynl$#_U7@jP?@)cAxeqU0I2xt^s$" ascii //weight: 1
        $x_1_2 = {b9 20 1f 00 00 f7 f1 8b 45 ?? 03 55 ?? 8b 4d ?? 0f b6 04 02 8b 55 ?? 30 04 0a 41 89 4d ?? 3b cf b9 20 1f 00 00 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_RWA_2147805853_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.RWA!MTB"
        threat_id = "2147805853"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "C6Ne<&!n7b?TKj0wku<)yQKB3xBs(OyE04(u1fxyib5hh(BSEDxRasVb<5lveJB7A&Wh5Qk4l)U1XJLO0yKdMggRSSd*f5" ascii //weight: 5
        $x_5_2 = "%qQn1+%2DtahH8KP%_JEsNTIeFuWp46O<sq5j2iVN0tl(mSbqgb5zh2)YQ$D5s^8j" ascii //weight: 5
        $x_1_3 = {33 d2 f7 35 ?? ?? ?? ?? 03 ca 8d 04 71 8a 0c 38 8b 44 24 ?? 30 08 ff 44 24 ?? 8b 44 24 ?? 3b 44 24 ?? 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotetcrypt_RWB_2147805908_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.RWB!MTB"
        threat_id = "2147805908"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "vVjQOkPOdK>^FOEGKl^0Q@z_m%6(@ZvueF_%" ascii //weight: 1
        $x_1_2 = {03 cf 03 ce 2b ca 8b 45 ?? 2b c8 2b 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 8b 55 ?? 8b 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_RWB_2147805908_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.RWB!MTB"
        threat_id = "2147805908"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 30 00 00 8b 95 ?? ?? ?? ?? 52 6a 00 6a ff ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = "(R0<m<sa?h%2xCjb7!dDG$*e4*i8p!3Uutm*gBvCy4rMdr3Fzfg)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_DP_2147805933_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.DP!MTB"
        threat_id = "2147805933"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 68 00 30 00 00 ff 73 ?? 2b c8 6a 00 89 4c 24 ?? ff d1}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 54 24 2c 4b 8b 4c 24 20 8b c3 25 ff 03 00 00 88 0c 10 8b 4f f8 8b 17 03 cd 03 54 24 14 8b 77 fc 85 f6 74 ?? 8a 02 8d 49 01 88 41 ff 8d 52 01 83 ee 01 75 ?? 83 c7 28 85 db 75}  //weight: 1, accuracy: Low
        $x_1_3 = "rust_panic" ascii //weight: 1
        $x_1_4 = "RaiseException" ascii //weight: 1
        $x_1_5 = "Control_RunDLL" ascii //weight: 1
        $x_1_6 = "ahnztsckyk" ascii //weight: 1
        $x_1_7 = "ajlvbnzvvkwabbiu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_DQ_2147806024_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.DQ!MTB"
        threat_id = "2147806024"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "52"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6a 40 68 00 30 00 00 ff 73 ?? 2b c8 6a 00 89 4c 24 ?? ff d1}  //weight: 10, accuracy: Low
        $x_10_2 = {8b 54 24 2c 4b 8b 4c 24 20 8b c3 25 ff 03 00 00 88 0c 10 8b 4f f8 8b 17 03 cd 03 54 24 14 8b 77 fc 85 f6 74 ?? 8a 02 8d 49 01 88 41 ff 8d 52 01 83 ee 01 75 ?? 83 c7 28 85 db 75}  //weight: 10, accuracy: Low
        $x_10_3 = "rust_panic" ascii //weight: 10
        $x_10_4 = "RaiseException" ascii //weight: 10
        $x_10_5 = "Control_RunDLL" ascii //weight: 10
        $x_1_6 = "akyncbgollmj" ascii //weight: 1
        $x_1_7 = "alrcidxljxybdggs" ascii //weight: 1
        $x_1_8 = "hajzbapcmgznq" ascii //weight: 1
        $x_1_9 = "pfoyaestkmmvbzyr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotetcrypt_DR_2147806025_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.DR!MTB"
        threat_id = "2147806025"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 01 0f b6 0a 03 c1 99 b9 c3 10 00 00 f7 f9 0f b6 04 2a 89 44 24 30}  //weight: 1, accuracy: High
        $x_1_2 = {8b 4c 24 34 8b 44 24 20 0f be 04 08 50 ff 74 24 20 e8 ?? ?? ?? ?? 59 59 8b 4c 24 34 ff 44 24 34 ff 4c 24 14 88 01 0f 85}  //weight: 1, accuracy: Low
        $x_1_3 = "PcyGIS0VJfQoH4m4056Z8utiBsHu66KD3bQP1BpZH6MTDz4KOmgpQITDOTWthQQT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_DS_2147806137_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.DS!MTB"
        threat_id = "2147806137"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d f4 0f b6 44 85 ?? 8d 0c 19 30 03 8d 5b 04 b8 ?? ?? ?? ?? f7 e1 8b 4d f0 c1 ea 03 8d 04 52 c1 e0 02 2b f0 0f b6 44 b5 ?? 30 43 fd 8d 04 19 3d 00 38 02 00 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_DT_2147806138_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.DT!MTB"
        threat_id = "2147806138"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d f0 0f b6 44 85 ?? 8d 0c 19 30 03 8d 5b 04 b8 ?? ?? ?? ?? f7 e1 8b 4d f8 c1 ea 03 8b c2 c1 e0 04 2b c2 2b f0 0f b6 44 b5 ?? 30 43 fd 8d 04 19 3d 00 38 02 00 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_DU_2147806139_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.DU!MTB"
        threat_id = "2147806139"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "52"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6a 40 68 00 30 00 00 ff 73 ?? 2b c8 6a 00 89 4c 24 ?? ff d1}  //weight: 10, accuracy: Low
        $x_10_2 = {8b 54 24 2c 4b 8b 4c 24 20 8b c3 25 ff 03 00 00 88 0c 10 8b 4f f8 8b 17 03 cd 03 54 24 14 8b 77 fc 85 f6 74 ?? 8a 02 8d 49 01 88 41 ff 8d 52 01 83 ee 01 75 ?? 83 c7 28 85 db 75}  //weight: 10, accuracy: Low
        $x_10_3 = "rust_panic" ascii //weight: 10
        $x_10_4 = "RaiseException" ascii //weight: 10
        $x_10_5 = "Control_RunDLL" ascii //weight: 10
        $x_1_6 = "axamexdrqyrgb" ascii //weight: 1
        $x_1_7 = "cegjceivzmgdcffk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_DV_2147806290_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.DV!MTB"
        threat_id = "2147806290"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "44"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6a 40 68 00 30 00 00 8b 49 ?? 83 c1 0c 51 6a 00 ff d0}  //weight: 10, accuracy: Low
        $x_10_2 = {48 89 44 24 20 3b cf 7e ?? e8 ?? ?? ?? ?? 8b 54 24 54 f2 0f 59 44 24 68 8a 02 42 89 54 24 54 8b 54 24 38 f2 0f 58 44 24 48 88 02 42 8b 44 24 20 f2 0f 11 44 24 48 89 54 24 38 85 c0 74 ?? f2 0f 10 44 24 78 8b 4c 24 1c eb}  //weight: 10, accuracy: Low
        $x_10_3 = "RaiseException" ascii //weight: 10
        $x_10_4 = "DllRegisterServer" ascii //weight: 10
        $x_1_5 = "asbiqstaeqzsycc" ascii //weight: 1
        $x_1_6 = "atwuhkycfybkj" ascii //weight: 1
        $x_1_7 = "bdkipyvq" ascii //weight: 1
        $x_1_8 = "bgbbytziolo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_RT_2147806387_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.RT!MTB"
        threat_id = "2147806387"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6b c0 13 2b c8 0f b6 44 8d ?? 30 43 ?? b8 cb 6b 28 af 8b 4d ?? 03 cb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_DW_2147806398_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.DW!MTB"
        threat_id = "2147806398"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 47 01 b8 ?? ?? ?? ?? 8b 4d ec 03 cf f7 e1 2b ca d1 e9 03 ca c1 e9 04 6b c1 13 8b 4d f8 2b f0 0f b6 84 b5 ?? ?? ?? ?? 30 47 02 83 c7 05 8d 04 0f 3d 00 30 02 00 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_DX_2147807225_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.DX!MTB"
        threat_id = "2147807225"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 44 05 d8 32 04 0e 88 01 8d 04 0b 83 e0 1f 0f b6 44 05 d8 32 42 fb 88 41 01 8b 45 cc 03 c1 83 e0 1f 0f b6 44 05 d8 32 42 fc 88 41 02 8b 45 c8 03 c1 83 e0 1f 0f b6 44 05 d8 32 42 fd 88 41 03 8d 04 17 83 c1 04 3d 00 32 02 00 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_DY_2147807330_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.DY!MTB"
        threat_id = "2147807330"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 04 68 00 30 00 00 6a 0a 6a 00 8b 45 08 8b 48 18 ff d1}  //weight: 1, accuracy: High
        $x_1_2 = {8b d1 80 7a 0c 00 75 ?? 33 c0 66 0f 1f 44 00 00 8b 0c 82 81 f1 e4 ed 77 3f 89 0c 82 40 83 f8 03 72}  //weight: 1, accuracy: Low
        $x_1_3 = "DllRegisterServer" ascii //weight: 1
        $x_1_4 = "kaod3r3y08cb0qx9lloha8h46a" ascii //weight: 1
        $x_1_5 = "ey79n4y9wg0awowjda00wqrmh6pt9g8" ascii //weight: 1
        $x_1_6 = "c8a2jkz7bq557c5f8mzzzgodexo73y" ascii //weight: 1
        $x_1_7 = "xgxd975rxajns9bzhpfzaavrupf" ascii //weight: 1
        $x_1_8 = "wq9om10n281h" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_RTH_2147807529_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.RTH!MTB"
        threat_id = "2147807529"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "psoldkjfnbsvcyudibnvscrgp" ascii //weight: 10
        $x_10_2 = "C:\\DLLPORTABLEX86\\32\\Release\\dll32smpl.pdb" ascii //weight: 10
        $x_1_3 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_4 = "GetCPInfo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_RTH_2147807529_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.RTH!MTB"
        threat_id = "2147807529"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Malformed JP2 file format" ascii //weight: 1
        $x_1_2 = "Z:\\cr\\crypter4\\ballast\\3\\openjp2\\opj_intmath.h" ascii //weight: 1
        $x_1_3 = "COMMON_CBLK_DATA_EXTRA" ascii //weight: 1
        $x_1_4 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_5 = "GetStartupInfoW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_RTS_2147807530_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.RTS!MTB"
        threat_id = "2147807530"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "kaod3r3y08cb0qx9lloha8h46a" ascii //weight: 1
        $x_1_2 = "d8hia1wys7lppa3s50lojt" ascii //weight: 1
        $x_1_3 = "ski9xoale4edpc3a6dx" ascii //weight: 1
        $x_1_4 = "ey79n4y9wg0awowjda00wqrmh6pt9g8" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_DZ_2147807587_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.DZ!MTB"
        threat_id = "2147807587"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6a 40 68 00 30 00 00 8b 4d f0 8b 51 50 52 8b 45 f0 8b 48 34 51 ff 15}  //weight: 10, accuracy: High
        $x_10_2 = {8b 55 f0 0f b7 42 06 39 45 dc 7d ?? 8b 4d e4 8b 51 10 52 8b 45 e4 8b 48 14 03 4d ec 51 8b 55 e4 8b 42 0c 03 45 e8 ?? ?? ?? ?? 07 00 83 c4 0c 8b 4d e4 83 c1 28 89 4d e4 eb}  //weight: 10, accuracy: Low
        $x_10_3 = {8b 4d dc 83 c1 01 89 4d dc 8b 55 f0 0f b7 42 06 39 45 dc 7d ?? 8b 4d e4 8b 51 10 52 8b 45 e4 8b 48 14 03 4d ec 51 8b 55 e4 8b 42 0c 03 45 e8 50 e8 ?? ?? ?? ?? 83 c4 0c 8b 4d e4 83 c1 28 89 4d e4 eb}  //weight: 10, accuracy: Low
        $x_1_4 = "DllRegisterServer" ascii //weight: 1
        $x_1_5 = "inflate" ascii //weight: 1
        $x_1_6 = "_opj_stream_destroy@4" ascii //weight: 1
        $x_1_7 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_8 = "Z:\\cr\\crypter4\\ballast\\3\\openjp2\\opj_intmath.h" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 5 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotetcrypt_EA_2147807636_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.EA!MTB"
        threat_id = "2147807636"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 14 37 8b 08 0f b6 04 33 03 c2 33 d2 f7 35 ?? ?? ?? ?? 8a 04 32 8b 55 ?? 32 04 11 8b 55 ?? ff 05 ?? ?? ?? ?? 88 04 11 a1 ?? ?? ?? ?? 3b 45 ?? 72}  //weight: 10, accuracy: Low
        $x_1_2 = "$hj%k0GA2?2*I8qSME35%yLhK05FAL1fgYz~p%CB~7cRo84GsaNHRocjh7khXQ3iQ2y|?K#YPqt" ascii //weight: 1
        $x_1_3 = "anfZ@uINFubgI3aPqPM?Nr%}IkS91S3qR2J#Rp*DlfdwhyRRl4C7#pjuXQNJrebq2ZpoRvGEwS%C" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotetcrypt_EC_2147807884_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.EC!MTB"
        threat_id = "2147807884"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 01 8b 4c 24 ?? 0f b6 11 03 c2 99 b9 74 02 00 00 f7 f9 a1 ?? ?? ?? ?? 88 54 24 11 8b 15}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 54 24 11 8b 0d ?? ?? ?? ?? 8a 14 0a 8b 45 08 30 14 06 46 3b 75 0c 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_RM_2147808243_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.RM!MTB"
        threat_id = "2147808243"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 e2 07 03 c2 8b c8 c1 f9 03 69 c9 b4 00 00 00 8b c7 2b c1 03 c6 8a c8 32 8d ?? ?? ?? ?? 85 db 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_RM_2147808243_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.RM!MTB"
        threat_id = "2147808243"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e6 02 0b d6 52 ff 74 24 ?? 53 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 59 f7 d8 50 ff 15 ?? ?? ?? ?? e9}  //weight: 1, accuracy: Low
        $x_1_2 = "<hxAweI_ZToNPZ2D$#Aau^b2+9mb8Y)@3etCCa?EOG*3rTy7dYbQJUaX^_dh$rN&%mPbC4W!cJ&M?<swVaS)R1gK844qfb*q&Jd4InSpPMf7A#$" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_ED_2147808456_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.ED!MTB"
        threat_id = "2147808456"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 04 68 00 30 00 00 6a 0a 6a 00 8b 45 08 8b 48 18 ff d1}  //weight: 1, accuracy: High
        $x_1_2 = "xofunl763t.dll" ascii //weight: 1
        $x_1_3 = "DllRegisterServer" ascii //weight: 1
        $x_1_4 = "e39x8hd7z5z098ocww3bhb32fl72fwa" ascii //weight: 1
        $x_1_5 = "iz1zj78roqtupt4f2yd2e65rg2" ascii //weight: 1
        $x_1_6 = "sj84n1j3nnrxwwa2dbhdtx" ascii //weight: 1
        $x_1_7 = "bt1vn1zjke30s47po" ascii //weight: 1
        $x_1_8 = "IsDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_EE_2147808653_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.EE!MTB"
        threat_id = "2147808653"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {6a 04 68 00 30 00 00 6a 0a 6a 00 8b 45 08 8b 48 18 ff d1}  //weight: 10, accuracy: High
        $x_10_2 = "o7h1zp8xfb.dll" ascii //weight: 10
        $x_10_3 = "DllRegisterServer" ascii //weight: 10
        $x_1_4 = "vs5xxc3ri6w5d6b" ascii //weight: 1
        $x_1_5 = "ymam87fdr14vcw74lr40bg" ascii //weight: 1
        $x_1_6 = "i1nxq1k0k82ratrljmsex6pq3j" ascii //weight: 1
        $x_1_7 = "wf8nga1z8n1f45uk6" ascii //weight: 1
        $x_1_8 = "ajb6uujmba7ljobupoyex1n5" ascii //weight: 1
        $x_1_9 = "d3xqz0rmc5ahg36t6tiw9m54cb" ascii //weight: 1
        $x_1_10 = "maj6ngjqe144qutzmpr7hrjr3s" ascii //weight: 1
        $x_1_11 = "wkxx5c7uhswbwatj3b3dmrx39dz1e" ascii //weight: 1
        $x_1_12 = "mwpjh0q78q0u8bcto0u6kkkhnutzc" ascii //weight: 1
        $x_1_13 = "ex3l0tydr8wm6mq5n1i1rkz84yy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 5 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotetcrypt_EF_2147808824_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.EF!MTB"
        threat_id = "2147808824"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "DllRegisterServer" ascii //weight: 10
        $x_1_2 = "eaonphlithyn.dll" ascii //weight: 1
        $x_1_3 = "aukjbzdloqqrfv" ascii //weight: 1
        $x_1_4 = "auxigugmftnxo" ascii //weight: 1
        $x_1_5 = "ckywegmtkvtcsn" ascii //weight: 1
        $x_1_6 = "eqqudqkdvqjbxvpwm" ascii //weight: 1
        $x_1_7 = "kqvkbphslzxqg.dll" ascii //weight: 1
        $x_1_8 = "enubqhyhrdravak" ascii //weight: 1
        $x_1_9 = "kjojhkittpozqpd" ascii //weight: 1
        $x_1_10 = "lmtrwlpwqtjhvtuj" ascii //weight: 1
        $x_1_11 = "macttvghbgxroesg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotetcrypt_EH_2147809100_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.EH!MTB"
        threat_id = "2147809100"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "gvtktwujzy.dll" ascii //weight: 10
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
        $x_1_3 = "IsProcessorFeaturePresent" ascii //weight: 1
        $x_1_4 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_5 = "RaiseException" ascii //weight: 1
        $x_1_6 = "arztoelaoghwuqg" ascii //weight: 1
        $x_1_7 = "bsibduodcowavzuy" ascii //weight: 1
        $x_1_8 = "btlvvdweagjdewdf" ascii //weight: 1
        $x_1_9 = "bvawnlfmqdqggvri" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_EJ_2147809864_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.EJ!MTB"
        threat_id = "2147809864"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 11 03 c2 33 d2 f7 35 ?? ?? ?? ?? 89 55 f8 8b 45 08 03 45 ec 33 c9 8a 08 8b 55 fc 03 55 f8 33 c0 8a 02 03 45 1c 33 c8 8b 55 18 03 55 ec 88 0a e9}  //weight: 1, accuracy: Low
        $x_1_2 = "q9L@Cpqfj&xNghMk7iM@Z)xrMI<EO)e!q5ZIWEElxTQ3PyF^7BhCoyW8(pji%f?d_fa<r@BIGfK7dw?+l@)3%AuP)5GQdn@?1T>t^lX^C5l49fhGdIG7+" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_EK_2147810025_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.EK!MTB"
        threat_id = "2147810025"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "DllRegisterServer" ascii //weight: 10
        $x_1_2 = "Project1.dll" ascii //weight: 1
        $x_1_3 = "_ZN8DllClass10HelloWorldEv" ascii //weight: 1
        $x_1_4 = "_ZN8DllClassC1Ev" ascii //weight: 1
        $x_1_5 = "_ZN8DllClassD0Ev" ascii //weight: 1
        $x_1_6 = "_ZTI8DllClass" ascii //weight: 1
        $x_1_7 = "zfdmcmfnupzgqzlteipdbor.dll" ascii //weight: 1
        $x_1_8 = "kleinxrgwlhiopf" ascii //weight: 1
        $x_1_9 = "rvqxdelnpcybiwlf" ascii //weight: 1
        $x_1_10 = "ubpyaepagvlenln" ascii //weight: 1
        $x_1_11 = "yfpjcyymhhut" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotetcrypt_EL_2147810026_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.EL!MTB"
        threat_id = "2147810026"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f af d8 a1 ?? ?? ?? ?? 0f af c3 8d 1c 06 a1 ?? ?? ?? ?? 29 c3 a1 ?? ?? ?? ?? 01 d8 89 c3 8b 45 08 01 d8 0f b6 00 31 c8 88 02 83 45 ec 01 8b 45 ec 3b 45 10 0f 82}  //weight: 10, accuracy: Low
        $x_1_2 = "RHq_HbXzNQ5TiH<%alp87Uq!6TL3m(akP0BKmQ65u5vHx>zNGcOvmVq*hIAmbUBjX#fZcCbn(%S)1&%zqHFIoxI+HmwMmll+AT5#Se31_%87@X1G@K" ascii //weight: 1
        $x_10_3 = {8b c3 0f af 05 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? 83 c0 04 0f af 05 ?? ?? ?? ?? 03 d0 8d 47 01 0f af c7 2b d0 8b 44 24 1c 2b d3 2b d1 8a 0c 32 30 08 8b 44 24 14 40 89 44 24 14 3b 44 24 2c 0f 82}  //weight: 10, accuracy: Low
        $x_1_4 = "oEhneZLJgKcFCKxbQcL!vadtOBC5X9#uwmgCXElu5oY40Y<B9V8x&L$OcLZPfvB3(%jyO_(h&<UDT&" ascii //weight: 1
        $x_1_5 = "OVs%m_p(yUBoEewX7f2XAaz!i^s3KnGg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotetcrypt_EM_2147810027_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.EM!MTB"
        threat_id = "2147810027"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MfcTTT" ascii //weight: 1
        $x_1_2 = "LayvXBcOppdgzCgnncA" ascii //weight: 1
        $x_1_3 = "MoveHis.txt" ascii //weight: 1
        $x_1_4 = "NoNetConnectDisconnect" ascii //weight: 1
        $x_1_5 = "NoRecentDocsHistory" ascii //weight: 1
        $x_1_6 = "RestrictRun" ascii //weight: 1
        $x_1_7 = "NoDrives" ascii //weight: 1
        $x_1_8 = "NoClose" ascii //weight: 1
        $x_1_9 = "NoRun" ascii //weight: 1
        $x_1_10 = "Game Over!" ascii //weight: 1
        $x_1_11 = "ShellExecuteW" ascii //weight: 1
        $x_1_12 = "GetFileType" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_EN_2147810241_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.EN!MTB"
        threat_id = "2147810241"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "DllRegisterServer" ascii //weight: 10
        $x_1_2 = "ldskoitipzlsph.dll" ascii //weight: 1
        $x_1_3 = "egimstorfmtycomkb" ascii //weight: 1
        $x_1_4 = "ejripkdhytkzx" ascii //weight: 1
        $x_1_5 = "epzxqgkqqerpxwqk" ascii //weight: 1
        $x_1_6 = "ioguxkfaxnhkcrxi" ascii //weight: 1
        $x_1_7 = "giwkhnjltp.dll" ascii //weight: 1
        $x_1_8 = "bahkgkxkdroklj" ascii //weight: 1
        $x_1_9 = "bkazzsdpctpmyra" ascii //weight: 1
        $x_1_10 = "ewoypwsbdapm" ascii //weight: 1
        $x_1_11 = "hmsecpcirudtpwdrb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotetcrypt_EO_2147810569_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.EO!MTB"
        threat_id = "2147810569"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "DllRegisterServer" ascii //weight: 10
        $x_1_2 = "n3feqfc9qd.dll" ascii //weight: 1
        $x_1_3 = "cy25bvwblz5eefhqaj5iouzv693le" ascii //weight: 1
        $x_1_4 = "eo1jf1ekoukjmdvhln9489ph" ascii //weight: 1
        $x_1_5 = "dy5du9ljnnkazcbq0uwb" ascii //weight: 1
        $x_1_6 = "xro0rur3iujnvtowzz32bvj4gsv25wx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_EP_2147810570_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.EP!MTB"
        threat_id = "2147810570"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d d4 2b c1 03 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8b 55 d8 03 d0 03 15 ?? ?? ?? ?? 8b 45 dc 2b d0 03 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 8b 4d e0 03 d1 2b 15 ?? ?? ?? ?? 8b 45 e4 2b d0 8b 4d 0c 8b 45 e8 88 04 11 e9}  //weight: 1, accuracy: Low
        $x_1_2 = "vzyxQQjtnPpM1kMtP2^c)toAOgGzJnA(x4n)mZV?Zgqbqls>&28Kb303hUncVaad@?N*A%W2eBhDNd+m_Bl2cFznqh*vrDpHPGj%?_!pbLp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_EQ_2147810571_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.EQ!MTB"
        threat_id = "2147810571"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 d0 2b ca 2b 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 8b 45 d4 03 c8 2b 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 8b 55 d8 03 d1 03 15 ?? ?? ?? ?? 8b 45 dc 2b d0 03 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 8b 4d e0 2b d1 8b 45 e4 2b d0 8b 4d 0c 8b 45 e8 88 04 11 e9}  //weight: 1, accuracy: Low
        $x_1_2 = "CQVFQNE^x0*<&CKsu95(PEWcK3UteF(FLX<yLEl?W8O%j&#2Cc%NV8F1PCg$c" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_ES_2147811066_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.ES!MTB"
        threat_id = "2147811066"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 14 1a 03 c2 33 d2 f7 35 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 e8 0f af e8 a1 ?? ?? ?? ?? 2b ce 0f af cf 03 e9 03 c0 2b e8 8b 44 24 20 2b ee 03 d3 8a 0c 6a 30 08}  //weight: 1, accuracy: Low
        $x_1_2 = "<zd*b0#t?rG7kzwFpXu%tW2r^@lhVjA?ozQ%KflFb?T0NiA#!Z8" ascii //weight: 1
        $x_1_3 = "^ZwPGwoWJf!vxNg46AOM3$JV0^y4Gcy9@S3+(Jgpo*_lhe+5hjRiNFg&lvbKBh2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_ET_2147811067_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.ET!MTB"
        threat_id = "2147811067"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 d8 2b f2 03 35 ?? ?? ?? ?? 2b 35 ?? ?? ?? ?? 03 35 ?? ?? ?? ?? 2b 35 ?? ?? ?? ?? 2b 35 ?? ?? ?? ?? 8b 45 dc 03 f0 8b 4d e0 03 f1 8b 55 e4 2b f2 03 35 ?? ?? ?? ?? 03 35 ?? ?? ?? ?? 2b 35 ?? ?? ?? ?? 2b 35 ?? ?? ?? ?? 03 35 ?? ?? ?? ?? 03 35 ?? ?? ?? ?? 8b 45 0c 8b 4d e8 88 0c 30 e9}  //weight: 1, accuracy: Low
        $x_1_2 = "Fov8OCWk&Z!oC0IpfJSl?%$k^t9%^mHdo*jy%Y?5b>QPs<XJbTD" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_EU_2147811068_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.EU!MTB"
        threat_id = "2147811068"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 54 24 30 0f b6 14 0a 89 44 24 18 8b c6 2b 44 24 10 bb ?? ?? ?? ?? 0f b6 04 38 03 c2 33 d2 f7 f3 8b 44 24 18 2b 54 24 34 03 d5 8a 14 3a 30 10}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 14 2a 03 c2 33 d2 bd ?? ?? ?? ?? f7 f5 8b 6c 24 44 8b c7 2b c1 2b c6 03 54 24 40 8d 04 82 8b 54 24 4c 03 c3 8a 04 10 30 45 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_EV_2147811069_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.EV!MTB"
        threat_id = "2147811069"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 08 8b f2 8b 54 24 ?? 8a 14 32 88 14 29 8b 54 24 ?? 88 04 32 8b 54 24 ?? 0f b6 14 0a 8b c6 2b 44 24 ?? bd ?? ?? ?? ?? 0f b6 04 18 03 c2 33 d2 f7 f5 8b 6c 24 ?? 03 54 24 ?? 0f b6 04 1a 30 44 2f ff}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 04 08 8b f2 8b 54 24 ?? 0f b6 14 32 88 14 29 8b 54 24 ?? 88 04 32 8b 44 24 ?? 0f b6 04 30 8b 54 24 ?? 0f b6 14 0a 03 c2 33 d2 bd ?? ?? ?? ?? f7 f5 8b 44 24 ?? 03 54 24 ?? 0f b6 14 02 30 54 3b ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_EW_2147811189_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.EW!MTB"
        threat_id = "2147811189"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 14 28 8b 54 24 ?? 8b 44 24 ?? 0f b6 04 02 8b 54 24 ?? 0f b6 14 2a 03 c2 33 d2 bd ?? ?? ?? ?? f7 f5 8b 44 24 ?? 2b d3 2b 15 ?? ?? ?? ?? 2b d6 03 15 ?? ?? ?? ?? 0f b6 14 02 30 54 0f ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_EX_2147811372_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.EX!MTB"
        threat_id = "2147811372"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 10 8b 54 24 ?? 8a 14 3a 88 14 2e 8b 54 24 ?? 88 04 3a 8b 44 24 ?? 0f b6 04 30 8b 54 24 ?? 0f b6 14 17 03 c2 33 d2 5d f7 f5 8b 44 24 ?? 8b 6c 24 ?? 03 54 24 ?? 8a 04 02 30 04 2b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_EY_2147811373_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.EY!MTB"
        threat_id = "2147811373"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 14 30 8b 44 24 ?? 88 14 08 8b 54 24 ?? 8a 44 24 ?? 88 04 32 8b 54 24 ?? 0f b6 04 32 8b 54 24 ?? 0f b6 14 0a 03 c2 33 d2 f7 f5 03 54 24 ?? 8b 44 24 ?? 03 d3 8a 14 02 8b 44 24 ?? 30 14 38}  //weight: 1, accuracy: Low
        $x_1_2 = "hbj^SbZMQo^+8ogqD*llLzG3U9vQ*I*1WRfl@EeBed3KW0%VK&LpuIr?@kTs0%*B#mk8_d@U*L7LMzVEvwu*uG6rjGxqXW1qU!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_EZ_2147811374_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.EZ!MTB"
        threat_id = "2147811374"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 08 8b 6c 24 ?? 8b f2 8b 54 24 ?? 8a 14 32 88 14 29 8b 54 24 ?? 88 04 32 8b 44 24 ?? 0f b6 04 30 8b 54 24 ?? 0f b6 14 0a 03 c2 33 d2 bd ?? ?? ?? ?? f7 f5 8b 44 24 ?? 8b 6c 24 ?? 03 54 24 ?? 03 d7 8a 04 02 30 04 2b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_FA_2147811375_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.FA!MTB"
        threat_id = "2147811375"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 14 32 88 14 29 8b 54 24 ?? 88 04 32 8b 44 24 ?? 0f b6 04 30 8b 54 24 ?? 0f b6 14 0a 03 c2 33 d2 bd ?? ?? ?? ?? f7 f5 8b 44 24 ?? 8b 6c 24 ?? 83 c5 01 89 6c 24 ?? 03 d3 03 54 24 ?? 03 d7 0f b6 14 02 8b 44 24 ?? 30 54 28 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_FB_2147811454_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.FB!MTB"
        threat_id = "2147811454"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b ca 03 0d ?? ?? ?? ?? 8b 45 d4 03 c8 8b 55 d8 2b ca 03 0d ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 8b 45 dc 2b c8 8b 55 e0 2b ca 8b 45 e4 2b c8 2b 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 8b 55 0c 8b 45 e8 88 04 0a}  //weight: 1, accuracy: Low
        $x_1_2 = "bIS!b!U341MxV)Qu65x^EQq&W4505L)me8arjn5e#L0by^V!!X?2JyqmPg@" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_FC_2147811482_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.FC!MTB"
        threat_id = "2147811482"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6a 00 6a 40 68 00 30 00 00 8b 4d d0 51 6a 00 6a ff ff 15}  //weight: 5, accuracy: High
        $x_5_2 = {6a 40 ba 00 20 00 00 2b 15 ?? ?? ?? ?? 81 ca 00 10 00 00 52 8b 45 d0 50 6a 00 ff 15}  //weight: 5, accuracy: Low
        $x_5_3 = "DllRegisterServer" ascii //weight: 5
        $x_1_4 = "6p2Z6a6CZ&M>ZR$a@Y$xnQ?<XBeh<22mz&0" ascii //weight: 1
        $x_1_5 = "kxnY_L?zqlSEuu5S2VFol6SH1q?86X^fU74B" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotetcrypt_FD_2147811613_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.FD!MTB"
        threat_id = "2147811613"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b d1 03 15 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 2b d1 2b 15 ?? ?? ?? ?? 2b 15 ?? ?? ?? ?? 2b 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 2b 15 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 03 4d 08 0f b6 14 11 8b 4d 0c 0f b6 04 01 33 c2}  //weight: 1, accuracy: Low
        $x_1_2 = "iQuiwf%BY%h6ITSPo(@cLbH)yP0btsz+XPpJSJZ!^Pc#ygsU>BVf>mwBpHQ+hxxD5TRYeX2>i9b7x&HJwR#" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_FE_2147811614_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.FE!MTB"
        threat_id = "2147811614"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b c1 8b 4d 08 0f b6 04 01 8b 4d 0c 0f b6 14 11 33 d0 8b 45 f4 03 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8b 4d 0c 88 14 01}  //weight: 1, accuracy: Low
        $x_1_2 = "r%$WTNBfDXV+SN6O@FI_mT2MgRzF*xaVJbFKLfi5Mpd8FJ<b5" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_FF_2147811671_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.FF!MTB"
        threat_id = "2147811671"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b ea 03 eb 03 6c 24 ?? 0f b6 14 2e 03 c2 33 d2 f7 35 ?? ?? ?? ?? 8d 04 49 b9 03 00 00 00 2b c8 0f af cb 8d 04 7f 03 d1 2b d0 0f b6 0c 32 8b 44 24 ?? 30 08}  //weight: 1, accuracy: Low
        $x_1_2 = "LW0<H<rJy!(XSUpyW7lpkF#aV#VA2L%Zk<lDR3<B>raI?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_FG_2147811761_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.FG!MTB"
        threat_id = "2147811761"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 14 2f 03 c2 33 d2 f7 35 ?? ?? ?? ?? 58 2b c1 0f af c3 03 d0 8b 44 24 ?? 2b d6 8a 0c 3a 30 08 ff 44 24 ?? 8b 44 24 ?? 3b 44 24 ?? 0f 82}  //weight: 1, accuracy: Low
        $x_1_2 = "WCe%&g(98hGWfyhTNpvb>Gq)jxR_P*Whe8hC_^_giKBj51IJE5<CFw@9!G#@zO+iGn%(bGtugE3p!PFKxeXWTbcmcdf@v)#%TyZq#qZbq3)<Ou4Qj03TL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_FH_2147811762_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.FH!MTB"
        threat_id = "2147811762"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 14 11 33 d0 a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 8b 75 ?? 2b 35 ?? ?? ?? ?? 03 35 ?? ?? ?? ?? 03 35 ?? ?? ?? ?? 2b 35 ?? ?? ?? ?? 2b f1 2b 35 ?? ?? ?? ?? 03 35 ?? ?? ?? ?? 03 35 ?? ?? ?? ?? 2b 35 ?? ?? ?? ?? 2b f0 8b 45 ?? 88 14 30}  //weight: 1, accuracy: Low
        $x_1_2 = "UpBF9Hyu+bmL0YLppBWv!@ZfZQkabl&rh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_FI_2147811763_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.FI!MTB"
        threat_id = "2147811763"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 c4 03 f8 8b 4d c8 03 f9 8b 55 cc 03 fa 8b 45 d0 03 f8 2b 3d ?? ?? ?? ?? 8b 4d d4 03 f9 8b 55 d8 03 fa 8b 45 dc 03 f8 8b 4d e0 03 f9 8b 55 e4 03 55 0c 8b 45 e8 88 04 3a}  //weight: 1, accuracy: Low
        $x_1_2 = "PA?K)8AsJO+$rW4IPoiq5Jyf8qj!Opip5^nO>kh6cxuD7tq5C25r24)3_Hx1v+bmO18gN_yfE>D!Yrk6fB(6F5hlKryOx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_FL_2147811896_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.FL!MTB"
        threat_id = "2147811896"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "DllRegisterServer" ascii //weight: 10
        $x_1_2 = "ji6fyh7eh5.dll" ascii //weight: 1
        $x_1_3 = "l7iqbh7ito4hhpdrc0p" ascii //weight: 1
        $x_1_4 = "pbztfze6xf4nvmc0ecfhgsx5p3" ascii //weight: 1
        $x_1_5 = "rc9tvpcps2x4dcyqegzxbncqeh1o" ascii //weight: 1
        $x_1_6 = "yooai0wjx2ubrrbn5vmb43qzb5qp" ascii //weight: 1
        $x_1_7 = "hx57t9blc8.dll" ascii //weight: 1
        $x_1_8 = "a0j6zuwowgw0rn93tioqobxsiyck5" ascii //weight: 1
        $x_1_9 = "apmhn8wbw577z4yvdtliac8u70" ascii //weight: 1
        $x_1_10 = "aqcdqy7qm1080wp124fgkzaiiub826c" ascii //weight: 1
        $x_1_11 = "dnuoimyj4ay02p3hv9f9qlc1u1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotetcrypt_FO_2147811953_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.FO!MTB"
        threat_id = "2147811953"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "fcr5vichkz.dll" ascii //weight: 10
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
        $x_1_3 = "IsProcessorFeaturePresent" ascii //weight: 1
        $x_1_4 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_5 = "RaiseException" ascii //weight: 1
        $x_1_6 = "my8pa4rsfdskxiqtmwpldwc3nm0j" ascii //weight: 1
        $x_1_7 = "todardg84qhxla2yxt8y31rbppyp" ascii //weight: 1
        $x_1_8 = "umwuoe1b7u1f5cxf64az3c" ascii //weight: 1
        $x_1_9 = "wwtqw7tl4hbo4o5v2tynk55y6jw4s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_FP_2147812002_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.FP!MTB"
        threat_id = "2147812002"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "DllRegisterServer" ascii //weight: 10
        $x_1_2 = "hmqcbbinxgdknssclvd.dll" ascii //weight: 1
        $x_1_3 = "kcjoymahqgaigdcko" ascii //weight: 1
        $x_1_4 = "keqovgcoskeepcii" ascii //weight: 1
        $x_1_5 = "krzrqqjehorypgt" ascii //weight: 1
        $x_1_6 = "mcyxwlbsnxhufaa" ascii //weight: 1
        $x_1_7 = "dsomcocaaetvf.dll" ascii //weight: 1
        $x_1_8 = "bkqedytihcafddvnb" ascii //weight: 1
        $x_1_9 = "eodppshatyfehokge" ascii //weight: 1
        $x_1_10 = "hcpotrzeubhkkvnhs" ascii //weight: 1
        $x_1_11 = "jkcgetibalhdwmqd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotetcrypt_FQ_2147812003_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.FQ!MTB"
        threat_id = "2147812003"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "DllRegisterServer" ascii //weight: 10
        $x_1_2 = "ftooqablxjtm.dll" ascii //weight: 1
        $x_1_3 = "johslymmiybgamgax" ascii //weight: 1
        $x_1_4 = "kkasvtinokohtxbg" ascii //weight: 1
        $x_1_5 = "lamtwdexxbskzxdr" ascii //weight: 1
        $x_1_6 = "njaaliyjsyrkpnl" ascii //weight: 1
        $x_1_7 = "mob9n6izq8.dll" ascii //weight: 1
        $x_1_8 = "l07go50qf4orwh5ytuz" ascii //weight: 1
        $x_1_9 = "ou1qq787cejodtl3br8msdsi" ascii //weight: 1
        $x_1_10 = "zz1bw74wbpjmh1ig6cq9i9jkllf" ascii //weight: 1
        $x_1_11 = "l7rd6" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotetcrypt_FR_2147812004_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.FR!MTB"
        threat_id = "2147812004"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "DllRegisterServer" ascii //weight: 10
        $x_1_2 = "enwr4nrvc2.dll" ascii //weight: 1
        $x_1_3 = "dggp07httg2zmzhm2ax8iekje4kcmy4" ascii //weight: 1
        $x_1_4 = "s5whpr7j072vyoj7bgo" ascii //weight: 1
        $x_1_5 = "t65ikn6s9b6vszjirr" ascii //weight: 1
        $x_1_6 = "tcq784f9va848uvyp9g" ascii //weight: 1
        $x_1_7 = "fce1jnbt0m.dll" ascii //weight: 1
        $x_1_8 = "h1gyqmdxj0vayccf8xfmqbvw" ascii //weight: 1
        $x_1_9 = "jb6asohqxnhu8ktra4mxf" ascii //weight: 1
        $x_1_10 = "rpihli9mobg0w53surkg4" ascii //weight: 1
        $x_1_11 = "rrdvbzlbsnuqaasuyrducat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotetcrypt_FU_2147812150_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.FU!MTB"
        threat_id = "2147812150"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "DllRegisterServer" ascii //weight: 10
        $x_1_2 = "fcvj8s7j0y.dll" ascii //weight: 1
        $x_1_3 = "b9wfizhi33wxvaj7smqelf05op4l" ascii //weight: 1
        $x_1_4 = "bngse5ntkm9s3i48mu7pvq2yi12i2" ascii //weight: 1
        $x_1_5 = "ivq036jvc4gigaoaf094f202dzfk86" ascii //weight: 1
        $x_1_6 = "j3rp0le25fjtf33hzmm4wv64laqov" ascii //weight: 1
        $x_1_7 = "nr1nv21pc2.dll" ascii //weight: 1
        $x_1_8 = "asdaozjkqa9a024909dp287hs8j0rq" ascii //weight: 1
        $x_1_9 = "fvgurzo63rmxtez9ml7z3z3" ascii //weight: 1
        $x_1_10 = "g1b9gc0d8mdq6m51juaix" ascii //weight: 1
        $x_1_11 = "gwmh0wfi816d00ba2ahys39" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotetcrypt_FV_2147812151_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.FV!MTB"
        threat_id = "2147812151"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DllRegisterServer" ascii //weight: 1
        $x_1_2 = "keba1cqsq6.dll" ascii //weight: 1
        $x_1_3 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_4 = "IsProcessorFeaturePresent" ascii //weight: 1
        $x_1_5 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_6 = "GetCommandLineA" ascii //weight: 1
        $x_1_7 = "CreateMutexA" ascii //weight: 1
        $x_1_8 = "DeleteFileA" ascii //weight: 1
        $x_1_9 = "Sleep" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_FW_2147812278_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.FW!MTB"
        threat_id = "2147812278"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 d1 2b 15 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 2b d1 2b 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 8b 4d ?? 0f b6 14 11 8b 4d ?? 0f b6 04 01 33 c2 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 8b 75 ?? 2b f2}  //weight: 1, accuracy: Low
        $x_1_2 = "kFGJ^j89ws*EYxqFV0+6Tv_KoQKK^iVPkSMwcCmveNtAI?&I+6197u8R_eBlwO3iqfm@4!gqcX+$^" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_FX_2147812279_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.FX!MTB"
        threat_id = "2147812279"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 0c 0a 33 c8 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 8b 75 ?? 2b 35 ?? ?? ?? ?? 2b 35 ?? ?? ?? ?? 2b 35 ?? ?? ?? ?? 03 35 ?? ?? ?? ?? 2b 35 ?? ?? ?? ?? 2b 35 ?? ?? ?? ?? 03 35 ?? ?? ?? ?? 03 c6 03 05 ?? ?? ?? ?? 03 c2 03 05 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? 8b 55 ?? 88 0c 02}  //weight: 1, accuracy: Low
        $x_1_2 = "i5brxckid!<O*1v#nEaEOvHhKukAUTSX@Dt@tSfZ!wI$2yUgPr(EJsFDE%*!mdE*kcgCIihmv&feZ_V?E<9G^U" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_FY_2147812280_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.FY!MTB"
        threat_id = "2147812280"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 04 30 0f b6 0c 11 33 d2 03 c1 b9 ?? ?? ?? ?? f7 f1 8b 45 ?? 03 55 ?? 8b 4d ?? 0f b6 04 02 8b 55 ?? 30 04 0a 41 89 4d ?? 3b cf b9 ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
        $x_1_2 = "sU?j+BU#XF6zU<%EZo0G(sd1Qu?mGTWv)d++LaC(FbtmMqEgJI(3%v((5Ieo&dmkwgd2#H#Jsy)pwGwNp7??UYp%1tvlVleoiUPAdG2TWb1u" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_GA_2147812312_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.GA!MTB"
        threat_id = "2147812312"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b c1 2b 05 ?? ?? ?? ?? 8b 4d 08 0f b6 04 01 8b 4d 0c 0f b6 14 11 33 d0 8b 45 f4 2b 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8b 4d 0c 88 14 01 e9}  //weight: 1, accuracy: Low
        $x_1_2 = "c$&XKTS2fCzwS@qvJ$EqdIcSM87j38VbEV1+9<NDO7)XYjASTv>sT^LU%Z2%X?_BmVCQGy&REL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_GB_2147812393_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.GB!MTB"
        threat_id = "2147812393"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c2 33 d2 f7 35 ?? ?? ?? ?? 89 55 ec 8b 45 f4 03 05 ?? ?? ?? ?? 8b 4d ec 2b 0d ?? ?? ?? ?? 8b 55 08 0f b6 0c 0a 8b 55 0c 0f b6 04 02 33 c1 8b 4d f4 03 0d ?? ?? ?? ?? 8b 55 0c 88 04 0a}  //weight: 1, accuracy: Low
        $x_1_2 = "iCwtDF^sEkeT6fDP!I(GjU+arA8JhD<vM!R(kRE)ZHuz&6*u0L5EU5gcCt*l0nb1TEXnoXzq+$%XZz>W<n+ua)@ZVGA<qp+*y@ODOS!C4NAzPJTvs6V3" ascii //weight: 1
        $x_1_3 = "6iWeNqbHipZcebsoH2XTvWBfy?9!UpHjmH0t0r1F6iJu(Hz>8+4B!Q9ScpRVgyovLe#x(U7zB00Cmz0>ynl$#_U7@jP?@)cAxeqU0I2xt^s$" ascii //weight: 1
        $x_1_4 = "trN>GdGr0CaWhvrf#e_fpTvpgE+PU?U4kNJGW?zN?%BAoR8F+" ascii //weight: 1
        $x_1_5 = "sa?h%2xCjb7!dDG$*e4*i8p!3Uutm*gBvCy4rMdr3Fzfg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_GC_2147812394_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.GC!MTB"
        threat_id = "2147812394"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b ca 2b 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 03 d1 2b 15 ?? ?? ?? ?? 2b 15 ?? ?? ?? ?? 8b 4d 08 0f b6 14 11 8b 4d 0c 0f b6 04 01 33 c2 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 8b 35}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 04 10 33 d2 0f b6 0c 31 03 c1 b9 ?? ?? ?? ?? f7 f1 8b 45 fc 03 55 f8 8b 4d f0 0f b6 04 02 8b 55 ec 30 04 0a 41 89 4d f0 3b cf b9 ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
        $x_1_3 = {03 d0 2b 15 ?? ?? ?? ?? 2b 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 8b 45 08 0f b6 14 10 8b 45 0c 0f b6 0c 08 33 ca 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 0f af 35}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_GD_2147812418_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.GD!MTB"
        threat_id = "2147812418"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 14 32 03 c2 89 6c 24 20 99 bd ?? ?? ?? ?? f7 fd 8b 44 24 5c 8b 6c 24 24 83 c5 01 89 6c 24 24 03 d3 03 d1 03 d7 0f b6 14 02 8b 44 24 28 30 54 28 ff}  //weight: 1, accuracy: Low
        $x_1_2 = "4XG6K%FJAh7H5l^Orv#<AeS1@cKlwfiDdFU>BZ7LAlSu^31CCYR9R4XG9oaA_%wf^8" ascii //weight: 1
        $x_1_3 = {0f b6 14 3a 03 c2 99 bd ?? ?? ?? ?? f7 fd 8b 44 24 50 8b 6c 24 1c 03 d6 03 54 24 18 0f b6 14 02 30 54 2b ff 3b 5c 24 58 0f 82}  //weight: 1, accuracy: Low
        $x_1_4 = "akiGMa7nmHJoI8DI6J>_^Q7C6Y3GlGaV4@i7tMcv%cVAS>6@KqMH5E4LY$6xMO^rHep*r?cD^Cu1?)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_GE_2147812487_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.GE!MTB"
        threat_id = "2147812487"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b c8 2b 0d ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 03 0d ?? ?? ?? ?? a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 2b c8 2b 0d ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 03 0d ?? ?? ?? ?? a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 2b c8 8b 45 08 0f b6 0c 08 8b 45 0c 0f b6 14 10 33 d1}  //weight: 1, accuracy: Low
        $x_1_2 = "ATX#9Kqo@jSv%xDqb!iseuTyK72Fi%^0lMlu$ozm+o!rY?dwFiC$gup(V<BtCb%nSW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_GF_2147812504_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.GF!MTB"
        threat_id = "2147812504"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b d0 03 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 03 c2 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 03 c2 2b 05 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? 8b 55 08 0f b6 04 02 8b 55 0c 0f b6 0c 0a 33 c8}  //weight: 1, accuracy: Low
        $x_1_2 = "@D$Z$GJ%t4kNOqR%PDYlC+7S0K9y#cCTp)At<DwUatPC$#8Tk9*CuXud34d?iqKfxLr4qc1qo<" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_RTA_2147812505_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.RTA!MTB"
        threat_id = "2147812505"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ATX#9Kqo@jSv%xDqb!iseuTyK72Fi%^0lMlu$ozm+o!rY?dwFiC$gup(V<BtCb%nSW" ascii //weight: 1
        $x_1_2 = {6a 40 68 00 30 00 00 8b 4d ?? 51 6a 00 6a ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_GG_2147812545_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.GG!MTB"
        threat_id = "2147812545"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b c1 2b 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 03 c8 2b 0d ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 8b 45 08 0f b6 0c 08 8b 45 0c 0f b6 14 10 33 d1}  //weight: 1, accuracy: Low
        $x_1_2 = ")KP*fx6AavxGB#89gHU_4w?(Fp$KKj9xql5ucH?6Nsu+^1)7um27w7O5qM!?49abR*8yB+e8" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_GH_2147812600_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.GH!MTB"
        threat_id = "2147812600"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 04 18 0f b6 0c 0a 03 c1 b9 ?? ?? ?? ?? 99 f7 f9 8b 4d f4 2b 55 bc 03 55 b8 8a 04 32 8b 55 e8 30 04 0a 41 3b 4d 08 89 4d f4 b9 ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
        $x_1_2 = "YwaW)Ce*EfOSlNtIc3__wOJYZ%V$MzT%uXXRU2o6_A<AquF5Dt<9Rr8_0m?9CQPNl&w1vhDzi&pwMVJeUY&RvMs166CnQ)9&rb^9I%" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_GJ_2147812760_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.GJ!MTB"
        threat_id = "2147812760"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b ca 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 03 ca 2b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 2b ca 2b 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 2b ca 8b 55 08 0f b6 0c 0a 8b 55 0c 0f b6 04 02 33 c1}  //weight: 1, accuracy: Low
        $x_1_2 = "X>JTQ(DkT%xkH^8JpR@@8wXjyhZoyDEF7g#1kLDpm23pAI2ulwwyeV" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_GK_2147813099_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.GK!MTB"
        threat_id = "2147813099"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 0c 08 8b 45 0c 0f b6 14 10 33 d1 a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 8b 4d f4 03 0d ?? ?? ?? ?? 2b c8 8b 45 0c 88 14 08}  //weight: 1, accuracy: Low
        $x_1_2 = "HOEV>^y9J6xvYpMOnZvv@ckBMeUvJdU!%KVPJt!q3U9Gaf?VTZlYpls4<J38OffsyHsGOlKb+N0FI(?A" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_GL_2147813136_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.GL!MTB"
        threat_id = "2147813136"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 44 24 30 8d 4c 7d 00 2b ca 8a 0c 01 8b 44 24 28 8a 18 32 d9 8b 4c 24 38 88 18 8b 44 24 1c 40 3b c1 89 44 24 1c 0f 82}  //weight: 1, accuracy: High
        $x_1_2 = "ha1me5i^tbbI7r27dcl2M^05WqYd3*4vjtpwuNeX" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_GM_2147813463_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.GM!MTB"
        threat_id = "2147813463"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c7 0f af 3d ?? ?? ?? ?? 0f af c6 be 02 00 00 00 2b f0 0f af 35 ?? ?? ?? ?? 2b 74 24 ?? 8b 44 24 ?? 2b 74 24 ?? 2b f9 03 74 24 ?? 03 d5 8d 0c 7f 8d 14 72 8a 0c 11 30 08 8b 44 24 ?? 83 c0 01 3b 44 24 ?? 89 44 24 ?? 0f 82}  //weight: 1, accuracy: Low
        $x_1_2 = "Tg(T)&P*CT52DHJ3%LNHtWRMuAMRfZWvc!LvvM2phD71#k5PR6!7C)hLq>aOfgx%jrGo!eDR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_GN_2147813464_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.GN!MTB"
        threat_id = "2147813464"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b df 0f af de 0f af de 8d 5c 0b ?? 0f af df 03 d5 03 d3 2b d0 8b 44 24 ?? 03 d6 03 d1 0f b6 0c 02 8b 44 24 ?? 30 08 8b 44 24 ?? 83 c0 01 3b 44 24 ?? 89 44 24 ?? 0f 82}  //weight: 1, accuracy: Low
        $x_1_2 = "KJ*PPI>!3@33H%6?N3x>o>^8t3#Q9$cvJ6xE23S?!CE&Pywa(6Z3l0aBRLu(+XT?a" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_GO_2147813465_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.GO!MTB"
        threat_id = "2147813465"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b d1 8b 4d ?? 0f b6 14 11 8b 4d ?? 0f b6 04 01 33 c2 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 0f af 35 ?? ?? ?? ?? 8b 3d ?? ?? ?? ?? 0f af 3d ?? ?? ?? ?? 0f af 3d ?? ?? ?? ?? 8b 5d ?? 03 1d ?? ?? ?? ?? 2b 1d ?? ?? ?? ?? 2b df}  //weight: 1, accuracy: Low
        $x_1_2 = "xKTSN#^CKEoj>9tb#1<*MWTsv634k5bTRC7#e5)NjOXu6FCfwl@JBLpT0>VJx<yPUsA0KzNzEo90c%kT&G4A#MS4&" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_GP_2147813466_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.GP!MTB"
        threat_id = "2147813466"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 14 2a 03 c2 99 bb ?? ?? ?? ?? f7 fb 33 c0 40 2b c6 0f af 05 ?? ?? ?? ?? 47 0f af fe 2b c7 03 c1 2b 05 ?? ?? ?? ?? 03 d5 6b c0 05 8a 0c 10 8b 44 24 24 30 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_GQ_2147813467_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.GQ!MTB"
        threat_id = "2147813467"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b df 0f af de 2b dd 43 43 0f af d9 2b f1 03 54 24 2c 03 c3 8d 04 70 2b 05 ?? ?? ?? ?? c1 e1 02 03 05 ?? ?? ?? ?? 6a 04 5e 2b f1 0f af 35 ?? ?? ?? ?? 83 ee 0c 0f af f7 8d 04 82 8a 0c 06 8b 44 24 20 30 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_GR_2147813468_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.GR!MTB"
        threat_id = "2147813468"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c8 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 2b ca 2b 0d ?? ?? ?? ?? a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 03 c1 8b 4d f0 8b 55 08 0f b6 0c 0a 8b 55 0c 0f b6 04 02 33 c1 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 0f af 15}  //weight: 1, accuracy: Low
        $x_1_2 = "s&pW1VBVMba8E@r%UV_mj1G$2YOLSQ+LjC" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_GS_2147813547_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.GS!MTB"
        threat_id = "2147813547"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 14 1a 03 c2 99 f7 fd 8b ea 8b 15 ?? ?? ?? ?? 8b c2 0f af c2 0f af c1 8d 44 40 ?? 0f af c6 03 e8 8b c7 0f af c1 83 c0 03 0f af 05 ?? ?? ?? ?? 8d 04 40 03 e8 8d 04 bd ?? ?? ?? ?? 2b e8 8b 44 24 ?? 2b ea 03 e9 8a 0c 2b 30 08}  //weight: 1, accuracy: Low
        $x_1_2 = "ZJ6SjhK0_#r9E$ou>x0dvcZ?SDd&4gr!)QI$olfrn?v9ee" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_GT_2147813548_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.GT!MTB"
        threat_id = "2147813548"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 0c 1a 03 c1 99 b9 ?? ?? ?? ?? f7 f9 a1 ?? ?? ?? ?? 8d 0c 85 ?? ?? ?? ?? b8 ?? ?? ?? ?? 2b c1 0f af c6 8b c8 a1 ?? ?? ?? ?? 8d 04 c0 2b c8 83 e9 ?? 0f af cf 03 d1 8b 0d ?? ?? ?? ?? 8d 04 76 03 d0 8d 04 8d ?? ?? ?? ?? 2b d0 0f b6 0c 1a 8b 44 24 ?? 30 08}  //weight: 1, accuracy: Low
        $x_1_2 = "Sf&zWTW#0&KS&HyX#7fFHDrtUBt)GjeI+98ErdEK$gdK#R" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_GU_2147813569_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.GU!MTB"
        threat_id = "2147813569"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 14 2a 03 c2 99 bd ?? ?? ?? ?? f7 fd 8d 47 ?? 0f af 05 ?? ?? ?? ?? 40 0f af c7 8d 2c 76 2b c5 2b c1 83 e8 ?? 0f af c1 0f af cb 8b 6c 24 28 8d 4c 39 01 8d 4c 49 01 0f af cf 8b 3d ?? ?? ?? ?? 2b c1 8b 0d ?? ?? ?? ?? 03 c9 2b c1 8b 4c 24 ?? 03 c7 03 c6 03 d5 8a 14 42 8b 44 24 ?? 30 10}  //weight: 1, accuracy: Low
        $x_1_2 = "XN1Z@3)fSmk<bC6+wZx83*ob1EZlB%^ql8HMurftw" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_GV_2147813570_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.GV!MTB"
        threat_id = "2147813570"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 14 1a 03 c2 99 bd ?? ?? ?? ?? f7 fd a1 ?? ?? ?? ?? bd ?? ?? ?? ?? 2b e8 0f af e8 b8 ?? ?? ?? ?? 2b c1 0f af c1 b9 ?? ?? ?? ?? 2b ce 0f af 0d ?? ?? ?? ?? 03 d5 03 d0 8b 44 24 ?? 03 d1 8b 4c 24 ?? 2b d6 03 d7 8a 14 1a 30 10}  //weight: 1, accuracy: Low
        $x_1_2 = "Rdp9LKEDNqdC4X9KPyOxDRAl<A*J>a^!dtNez?PlX)6f(UGHT?^O3>V&m89Wc<9*3+tRdp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_GW_2147813577_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.GW!MTB"
        threat_id = "2147813577"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 14 1a 03 c2 99 bd ?? ?? ?? ?? f7 fd a1 ?? ?? ?? ?? 8b e9 0f af ce 0f af e8 0f af c8 0f af ef 45 0f af 2d ?? ?? ?? ?? 41 0f af ee 0f af cf 2b cd 8d 04 49 03 d3 8a 0c 10 8b 44 24 ?? 30 08}  //weight: 1, accuracy: Low
        $x_1_2 = "xa86uzZgLfBryN*UIX5cVWhMDstFZ*9D^^511B6NI6Kdb$0$j<6gS1jsBUIgBviC(_W^vs@Oy>q?9<#sFjq+<ofYXXj_" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_GX_2147813607_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.GX!MTB"
        threat_id = "2147813607"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 14 2a 03 c2 99 bd ?? ?? ?? ?? f7 fd 8d 04 3e 0f af c1 03 c0 8b e8 8b c3 0f af c6 8b f0 a1 ?? ?? ?? ?? 0f af f0 2b f5 03 54 24 ?? 2b c8 8b 44 24 ?? 0f af 05 ?? ?? ?? ?? 2b f7 83 ee ?? 0f af f3 8d 04 40 8d 0c 4e 2b c8 8b 44 24 ?? 2b cf 8a 0c 4a 30 08}  //weight: 1, accuracy: Low
        $x_1_2 = "r_xav$na2L)FOeT1#qD3SWR#DOQBz@h?&+hyJ%CbY*j1z%k(kSwUX$ELDIxwfuhbyDIe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_GY_2147813647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.GY!MTB"
        threat_id = "2147813647"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 d7 8d 3c 09 bd ?? ?? ?? ?? 2b ef 0f af ee bf ?? ?? ?? ?? 2b f8 8d 44 7d 00 0f af 05 ?? ?? ?? ?? 03 d0 a1 ?? ?? ?? ?? 8d 34 46 8d 04 85 ?? ?? ?? ?? 0f af c1 d1 e6 2b d6 03 d3 8a 0c 10 8b 44 24 ?? 8a 18 32 d9 8b 4c 24 ?? 88 18}  //weight: 1, accuracy: Low
        $x_1_2 = "a3tr7mx6BJrs7<fbT%Y(duJ(MvjR@0dAb5!Qm67)6CKvwUh7OUr0U_rXFhOwT)$kH9qw$U@k" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_GZ_2147813650_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.GZ!MTB"
        threat_id = "2147813650"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c3 0f af c3 8b 1d ?? ?? ?? ?? 0f af c7 03 e8 a1 ?? ?? ?? ?? 03 d1 0f af d8 8d 0c 36 be ?? ?? ?? ?? 2b f1 0f af f0 8d 44 7e ?? 0f af 05 ?? ?? ?? ?? 03 eb 2b 2d ?? ?? ?? ?? 8d 0c 6a 8a 14 08 8b 44 24 ?? 8a 18 8b 4c 24 ?? 32 da 88 18}  //weight: 1, accuracy: Low
        $x_1_2 = "e>zT#YyLIq8#0DXIcX7heOQG<H@+C!Gl^SIMapdk9@othM)jD^HJ^ogNGeW%w&Iz!G7GWf^x1t<KZmihU49bMy9tILwbD_U<zIx2ECQN)y8RCFWNd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_HA_2147813671_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.HA!MTB"
        threat_id = "2147813671"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 14 1a 03 c2 99 bd ?? ?? ?? ?? f7 fd a1 ?? ?? ?? ?? 8d 44 00 ?? 0f af 05 ?? ?? ?? ?? 03 d0 8d 0c 4a 8d 14 f5 ?? ?? ?? ?? 8b 44 24 ?? 2b d6 2b ca 0f b6 0c 19 30 08 83 c7 ?? 3b 7c 24 ?? 89 7c 24 ?? 0f 82}  //weight: 1, accuracy: Low
        $x_1_2 = "BW9CgRB$<JCPT$**ZPW3K##Yw&(neCSxBVD5?&!GM8RG&k1M" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_HB_2147813705_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.HB!MTB"
        threat_id = "2147813705"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f af ce 0f af ce 03 d3 bb ?? ?? ?? ?? 2b d9 8d 4e 01 0f af de 0f af c8 a1 ?? ?? ?? ?? 2b c8 2b ce c1 e1 02 2b c8 83 e9 05 0f af cf 03 c8 03 d3 03 ca 8b 15 ?? ?? ?? ?? 8d 04 91 8a 0c 28 8b 44 24 20 8a 18 32 d9 8b 4c 24 30 88 18}  //weight: 1, accuracy: Low
        $x_1_2 = "g2RcU*^vxK)e5+4^sesArLg(0UDX4PyWPy(EQ8VtJka4<9ZU$>HI%54?@Tf+BbF_)YW*!sVMvM4ya%7bCGkqBgHM&7Ir?I*4YucMR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_HC_2147813706_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.HC!MTB"
        threat_id = "2147813706"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 04 80 03 d8 a1 ?? ?? ?? ?? 0f af d9 6b c9 fd 03 eb 8d 5e 04 0f af d8 2b cb 2b ce 03 ca 8d 50 02 0f af d6 8d 04 42 8d 04 80 8d 4c 8d 00 2b c8 8b 44 24 24 8a 18 8a 0c 39 32 d9 8b 4c 24 34 88 18}  //weight: 1, accuracy: Low
        $x_1_2 = "S+jOlCGfd6hheC+yeaM7(s5pR63oNhMPbt*q3QhXx*&hM)9&&<Er5^U7rl!<RVZB)wnsI2aRW@@84wSU?2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_HD_2147813707_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.HD!MTB"
        threat_id = "2147813707"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 d2 2b ea 8b 15 ?? ?? ?? ?? 03 ea 8d 2c a8 8b 44 24 20 83 c0 01 0f af c2 03 c6 0f af 05 ?? ?? ?? ?? 03 c6 0f af f7 03 c7 03 c1 8d 0c b5 ?? ?? ?? ?? 0f af cb 83 c1 04 0f af cb 8d 04 40 2b e8 03 6c 24 2c 8b 44 24 24 0f b6 14 29 30 10}  //weight: 1, accuracy: Low
        $x_1_2 = "yerYXW8&MxO(i!Kvk>(_ig)!hM72c$Hwfd+IE7*" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_HE_2147813750_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.HE!MTB"
        threat_id = "2147813750"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 14 0a 03 c2 99 b9 ?? ?? ?? ?? f7 f9 a1 ?? ?? ?? ?? b9 ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 2b c8 0f af ce 03 c0 2b c5 03 d1 8d 0c 42 8b 54 24 20 8b 44 24 2c 83 c2 02 0f af 15 ?? ?? ?? ?? 2b ca 03 cf 03 cb 8a 0c 01 8b 44 24 24 30 08}  //weight: 1, accuracy: Low
        $x_1_2 = "xuAE<kWdlyC*i3VsIRYv@YHNgk4hY5GBp0UhJ5ZrmwJ_OmBTh@41fD" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_HF_2147813756_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.HF!MTB"
        threat_id = "2147813756"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 14 1a 03 c2 99 bb ?? ?? ?? ?? f7 fb a1 ?? ?? ?? ?? 8b da 8b 15 ?? ?? ?? ?? 03 5c 24 ?? 8b ea 2b ee 03 e9 8d 74 28 ff 0f af 35 ?? ?? ?? ?? 8d 68 01 0f af e8 2b 6c 24 20 2b ef 2b e9 8d 04 6e 2b c2 2b c1 8d 04 40 0f b6 0c 18 8b 44 24 24 30 08}  //weight: 1, accuracy: Low
        $x_1_2 = "mU%IpYzYJ<chee34Pt0lLweNc!u!RVzEBEGp(x8*eilQ<hquc09r1Ah>IwOrWQ_G6gu(3c@6yM#lIBRlJtLGay!Z@w&XTSy626t" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_HG_2147813835_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.HG!MTB"
        threat_id = "2147813835"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 d0 8b 4d f0 2b 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 8b 45 08 0f b6 0c 08 8b 45 0c 0f b6 14 10 33 d1 a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 8b 4d f4 2b 0d ?? ?? ?? ?? 03 45 0c 88 14 08}  //weight: 1, accuracy: Low
        $x_1_2 = "(PybznxQNi<zikyMTVeMmU)jOO^TE@U>>FlK!M0oRPJgx6Cy?oHygc0kt>fF&&Ify)Po2k(Q+DOb8oT!*Q9fQ#O6i4fM#u2Q" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_HH_2147813836_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.HH!MTB"
        threat_id = "2147813836"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c1 2b 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? 8b 4d 08 0f b6 04 01 8b 4d 0c 0f b6 14 11 33 d0 a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 0f af 35 ?? ?? ?? ?? 8b 3d ?? ?? ?? ?? 0f af 3d ?? ?? ?? ?? 8b 1d ?? ?? ?? ?? 0f af 1d ?? ?? ?? ?? 89 55 e8}  //weight: 1, accuracy: Low
        $x_1_2 = "82y@kos<e9b?$#UfUSTFEdpuGv@K8%uK(1$b7OtM+%6K5b>j" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_HI_2147813845_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.HI!MTB"
        threat_id = "2147813845"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 d1 2b 15 ?? ?? ?? ?? 2b 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 2b 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 03 d1 2b 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 8b 4d 08 0f b6 14 11 8b 4d 0c 0f b6 04 01 33 c2 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 0f af 15}  //weight: 1, accuracy: Low
        $x_1_2 = "_vaZ&St3giE1Pr!b()(SwTdK6I7a#ObGCJjH1tFI4uq&*bVb%9O36LM&I&" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_HJ_2147813847_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.HJ!MTB"
        threat_id = "2147813847"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b d0 03 15 ?? ?? ?? ?? 2b 15 ?? ?? ?? ?? 2b 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 2b 15 ?? ?? ?? ?? 2b 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 2b d0 a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 2b d0 8b 45 08 0f b6 14 10 8b 45 0c 0f b6 0c 08 33 ca 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 0f af 35 ?? ?? ?? ?? 0f af 35}  //weight: 1, accuracy: Low
        $x_1_2 = "!lXp*8oZPGLaZjL!w2F24PhdsII30P8%v^(b<2wkhcyADHuirw(070<A_)>L>Avm$" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_HK_2147813922_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.HK!MTB"
        threat_id = "2147813922"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b ca 2b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 2b c8 8d 8c 8f 00 10 00 00 8d 04 95 00 20 00 00 0b c8 51 56 55 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = "folder.dll" ascii //weight: 1
        $x_1_3 = "DllRegisterClass" ascii //weight: 1
        $x_1_4 = "DllRegisterServer" ascii //weight: 1
        $x_1_5 = "DllUnregisterServer" ascii //weight: 1
        $x_1_6 = "hhctrl.ocx" ascii //weight: 1
        $x_1_7 = "ColorSelector MFC Application" ascii //weight: 1
        $x_1_8 = "NoNetConnectDisconnect" ascii //weight: 1
        $x_1_9 = "NoRecentDocsHistory" ascii //weight: 1
        $x_1_10 = "NoEntireNetwork" ascii //weight: 1
        $x_1_11 = "NoBackButton" ascii //weight: 1
        $x_1_12 = "NoPlacesBar" ascii //weight: 1
        $x_1_13 = "NoRemove" ascii //weight: 1
        $x_1_14 = "NoDrives" ascii //weight: 1
        $x_14_15 = {0f b6 04 30 03 c3 99 bb ?? ?? ?? ?? f7 fb 03 54 24 ?? 8b da 8b 54 24 ?? 8a 04 32 8b 54 24 ?? 0f b6 14 1a 88 14 2e 8b 54 24 ?? 88 04 1a 8b 44 24 ?? 0f b6 04 30 8b 54 24 ?? 0f b6 14 1a 03 c2 99 bd ?? ?? ?? ?? f7 fd 8b 44 24 ?? 8b 6c 24 ?? 03 d7 0f b6 14 02 30 54 29}  //weight: 14, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((14 of ($x_1_*))) or
            ((1 of ($x_14_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotetcrypt_HL_2147813923_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.HL!MTB"
        threat_id = "2147813923"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 04 0a 03 c3 99 f7 fe 8b 44 24 ?? 8a 04 08 8b 74 24 ?? 2b 54 24 ?? 8b da 8b 54 24 ?? 0f b6 14 1a 88 14 0e 8b 54 24 ?? 88 04 1a 8b 44 24 ?? 0f b6 04 18 8b 54 24 ?? 0f b6 14 0a 03 c2 99 be ?? ?? ?? ?? f7 fe 8b 44 24 ?? 8b 74 24 ?? 2b d7 03 54 24 ?? 0f b6 14 02 30 54 2e}  //weight: 1, accuracy: Low
        $x_1_2 = "+^lc?FUPR%6D6@hW^@hZu0RYT5tz+auO$ZYZa5DctZ9>+%cuRY%u*19n" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_HM_2147813924_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.HM!MTB"
        threat_id = "2147813924"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "63"
        strings_accuracy = "Low"
    strings:
        $x_50_1 = {03 d5 2b d0 b8 00 04 00 00 2b c1 03 c0 03 c0 81 c2 00 10 00 00 03 c0 0b d0 52 57 53 ff 15}  //weight: 50, accuracy: High
        $x_50_2 = {8d bc ab 00 10 00 00 8d 5a 02 0f af 1d ?? ?? ?? ?? 2b 1d ?? ?? ?? ?? 2b 1d ?? ?? ?? ?? 03 da 8d 84 58 00 20 00 00 0b f8 57 56 6a 00 ff 15}  //weight: 50, accuracy: Low
        $x_1_3 = "phinl.dll" ascii //weight: 1
        $x_1_4 = "DllRegisterClass" ascii //weight: 1
        $x_1_5 = "DllRegisterServer" ascii //weight: 1
        $x_1_6 = "DllUnregisterServer" ascii //weight: 1
        $x_1_7 = "hhctrl.ocx" ascii //weight: 1
        $x_1_8 = "ColorSelector MFC Application" ascii //weight: 1
        $x_1_9 = "NoNetConnectDisconnect" ascii //weight: 1
        $x_1_10 = "NoRecentDocsHistory" ascii //weight: 1
        $x_1_11 = "NoEntireNetwork" ascii //weight: 1
        $x_1_12 = "NoBackButton" ascii //weight: 1
        $x_1_13 = "NoPlacesBar" ascii //weight: 1
        $x_1_14 = "NoRemove" ascii //weight: 1
        $x_1_15 = "NoDrives" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 13 of ($x_1_*))) or
            ((2 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotetcrypt_HN_2147813980_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.HN!MTB"
        threat_id = "2147813980"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 14 2a 03 c2 99 bd ?? ?? ?? ?? f7 fd 8b ee 2b ef 0f af 2d ?? ?? ?? ?? 83 c5 03 0f af e9 8b c7 2b c6 83 e8 05 0f af c3 03 e8 a1 ?? ?? ?? ?? 03 54 24 2c 2b c8 0f af cf 03 e9 2b e8 8b 44 24 24 6b ed 03 8a 0c 2a 30 08}  //weight: 1, accuracy: Low
        $x_1_2 = {0f af c1 8b eb 2b e8 8b c7 0f af c6 45 0f af e9 03 2d ?? ?? ?? ?? 40 0f af c3 8b df 0f af de 0f af de 03 c5 6b db 03 6b c0 03 03 d0 a1 ?? ?? ?? ?? 83 c3 04 0f af df 8b f8 6b ff 03 8d 7c 3b ff 0f af f8 03 7c 24 28 8b 44 24 20 2b ce 49 0f af ce 03 fa 8a 0c 8f 30 08}  //weight: 1, accuracy: Low
        $x_1_3 = "ioJWT8ckiz9iT>_KLO0FiY95u@GjVFR*hl8<d3ewW+Da)gagIMNfn+<3?MyG&T4KLEuy^d?pfZ<7FMkEHD^sY>KINeVpH)kZ_cgUYXSt7c+$o3HN__lU?jXl" ascii //weight: 1
        $x_1_4 = "FIn7_Tw5mR!SaGJ5&8tUN!Hfih&pvX!<ES!O9xef4pSmSyg8W*@bH3k@HRk??0<&yOdLU+4OU8p<" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_HO_2147814028_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.HO!MTB"
        threat_id = "2147814028"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b c2 2b 05 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 2b c2 2b 05 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 2b c2 2b 05 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? 8b 55 08 0f b6 04 02 8b 55 0c 0f b6 0c 0a 33 c8 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 0f af 05}  //weight: 1, accuracy: Low
        $x_1_2 = "y9tSub&jeRk^OI!9_)Z_PD!J^uZd&!l*Xx)Qz9I?lUK?k8lwlOWlQwDL9WUWJ?yTrCWHHgZX<jw4QOVET(ftdO2Az3" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_HP_2147814029_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.HP!MTB"
        threat_id = "2147814029"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b ca 2b 0d ?? ?? ?? ?? 03 0d ?? ?? ?? ?? a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 2b c8 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 03 ca 2b 0d ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 8b 45 f0 2b 05 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? 8b 55 08 0f b6 04 02 8b 55 0c 0f b6 0c 0a 33 c8 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 0f af 05}  //weight: 1, accuracy: Low
        $x_1_2 = "@nq3(0mgd3Y$zxZnV_PComJXoU%Y&UP7)woj<OIjaKP8>RI7pagHZQ7!$>GdPc_z_rJyv!ZcByoGzMSDmkL&I5(r$s5Ug90RMHIO" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_HQ_2147814030_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.HQ!MTB"
        threat_id = "2147814030"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "E!r3#DUGVM)Dt7rai&CI@GEtP#0lHDtE9_p?_E$9a*F5vK64t3$_(dZJO0eXH?^vbYKtZ9MDNYdhE<MNLVuV5HBDOY)C8E@_V%" ascii //weight: 1
        $x_1_2 = "QrpZQSG*?VZl5@In^H0fW@s939rMxfS2hdhZ%V*CTZd1O)U_ef)W7oU_2fyr<1SIfGH0E!dKzX&n" ascii //weight: 1
        $x_1_3 = "cE^Dqd9g7lHK0LA7TpI(jXO%zw%r@bRxyq#LacQJXUlXkrEM69n@MICe6AUUt3i4_XGyp<" ascii //weight: 1
        $x_1_4 = "n8cNvPBhSs>sW@pqwJWf?<H%8i!%>(^VT9!^)BDiMM05f!Tq2uHFHRbbFYKb6V$offmsR2ZZnd8SfdNSw9Yx%zaln?*#JviUqq*Nl<4y1^wy%" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_HR_2147814071_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.HR!MTB"
        threat_id = "2147814071"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "jVp>0#Lz6PeS+(ViaP!8SsAF!hz&*9q#ovYatMI&rXKx6qG*G5xz_3(hkv6dMwd?aKNjOjm?dY)!+!^OFTYGV" ascii //weight: 1
        $x_1_2 = "2(M)z)^3^C$nc(mN*doJObwX00&E)koKXXhucrUR$<&X#C+UYAKnv)$3u3DvivsR<swY@RyqbDS1oQNa(SWPPO8_PbulJREK@r!ucP+vB1AH7kN%" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_HS_2147814119_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.HS!MTB"
        threat_id = "2147814119"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rJ_9IH+4mllGb3%jBW$k%a15sE<xu5R@K8D!ltyrHmn6QGp?ZelMJ0itJlYMeFENg#tg_NrFEi0WkFzcR1j7rw+>a!d$fim#zMFQ4qQo$wcbISt" ascii //weight: 1
        $x_1_2 = "zzqy_0Qyl5ea>xh8jT_jrm75H^&Fe#Vjt(D8XOmFcnasj5CXu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_HT_2147814150_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.HT!MTB"
        threat_id = "2147814150"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "^*&S5FAd<7P<R!Vs!z$ckou>U(t!Od^UiR>wJV3J7Av_27_&hC6ZMYSrmes$n03kZDbqK*QZ>C@^NJ%f!bj$l@DvJ*&@D<3!" ascii //weight: 1
        $x_1_2 = "zA?X<sR0Jp#5QjX?EzlwXCht*tB1&<DR$)Cq3BuvcNAi9K1(RC1e?XTc$Z)v0826T%fP(fqndtpn1_DwR2FxMrQjchLY_y(@!&GkE9YQDpnT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_HU_2147814330_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.HU!MTB"
        threat_id = "2147814330"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 14 2b 03 c2 99 bd ?? ?? ?? ?? f7 fd a1 ?? ?? ?? ?? 0f af c7 5d 2b e8 0f af e9 8d 44 0f 02 0f af c6 2b e8 a1 ?? ?? ?? ?? 0f af c0 03 e8 6b ed 03 03 d5 8d 04 09 2b d0 2b 54 24 20 8b 44 24 2c 03 15 ?? ?? ?? ?? 03 d6 8a 0c 1a 30 08}  //weight: 1, accuracy: Low
        $x_1_2 = "FW4B1WqO0Hmr@&tp_z<1uGyHcF>P^EI9&SHA<S*i1pu^N&" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_HV_2147814331_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.HV!MTB"
        threat_id = "2147814331"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 04 30 8b 54 24 10 0f b6 14 0a 03 c2 99 bd ?? ?? ?? ?? f7 fd 8b 44 24 60 8b 6c 24 1c 2b 54 24 50 03 d3 03 54 24 54 03 54 24 58 8a 04 02 30 04 2f 45 3b 6c 24 68 89 6c 24 1c 0f 82}  //weight: 1, accuracy: Low
        $x_1_2 = "gIqLTwRe?&3xnV+hMC1VDTTV#%_ifbWi@CS$?FrIve?96#jCH_8X5>KbYQ307JytIk8vZaqWG22aFaHtig(^ew_0$4WTz*eS<nHd8SJ^dqYp!3lp)" ascii //weight: 1
        $x_1_3 = "zA?X<sR0Jp#5QjX?EzlwXCht*tB1&<DR$)Cq3BuvcNAi9K1(RC1e?XTc$Z)v0826T%fP(fqndtpn1_DwR2FxMrQjchLY_y(@!&GkE9YQDpnT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_HW_2147814371_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.HW!MTB"
        threat_id = "2147814371"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 60 8b 7d 08 8b 75 0c 8b 4d 10 8b 55 14 ac 30 d0 aa c1 ca 08 e2}  //weight: 1, accuracy: High
        $x_1_2 = {80 3a 00 74 ?? ac 32 02 aa 42 e2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_AB_2147814403_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.AB!MTB"
        threat_id = "2147814403"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "p6Nwk3*A3IcEIKe$J>Iei<?GRd4jyc09YREa@+TY<!e+EXBSEDXnYnwpE<iW%sjVY80C^sc<AQ#wcWuMpbO(tiBUmD^TrN(5b)+trZvqLV5$A*71VZ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_IB_2147814413_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.IB!MTB"
        threat_id = "2147814413"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 14 1a 03 c2 99 bd ?? ?? ?? ?? f7 fd 8b 44 24 54 8b 6c 24 18 83 c5 01 89 6c 24 18 03 d7 03 d6 0f b6 14 02 8b 44 24 20 30 54 28 ff 3b 6c 24 5c 0f 82}  //weight: 1, accuracy: Low
        $x_1_2 = "p!c!X8<0aiR1>fkdymE<X!!xfdtZ?<*&nJxRZz9Voy!&q3*ITkF57r@_EaCLz" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_HX_2147814441_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.HX!MTB"
        threat_id = "2147814441"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b c1 03 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 2b c1 8b 4d 08 0f b6 04 01 8b 4d 0c 0f b6 14 11 33 d0 8b 45 f4 2b 05 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? 8b 4d 0c 88 14 01}  //weight: 1, accuracy: Low
        $x_1_2 = "_8XnHiDzMFTwO$D<Reg+7Jwrim6h@I5!Rks#siJxDSL5kYy21ZlqSe0UA8RmQ)A*nz00jOJO12$h<DXA5c5tzp3)S" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_HY_2147814538_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.HY!MTB"
        threat_id = "2147814538"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b c8 2b 0d ?? ?? ?? ?? a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 2b c8 a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 2b c8 03 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 8b 45 08 0f b6 0c 08 8b 45 0c 0f b6 14 10 33 d1 a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 8b 0d}  //weight: 1, accuracy: Low
        $x_1_2 = "u2VV7XXg*?q4brxSy2jKuo)j^UUtFW?(*" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_HZ_2147814570_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.HZ!MTB"
        threat_id = "2147814570"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 d1 2b 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 03 d0 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 03 d1 8b 45 f0 03 05 ?? ?? ?? ?? 8b 4d 08 0f b6 04 01 8b 4d 0c 0f b6 14 11 33 d0 a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 8b 0d}  //weight: 1, accuracy: Low
        $x_1_2 = "y(3ZodtY8zA_xI##_P0g>qx6^!_IGnMvTm*z&sbr@nY" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_IA_2147814598_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.IA!MTB"
        threat_id = "2147814598"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "!rNKV0%MW?OyANFn><tvDn8C!NKc_X(+DrLc6sIrJw27(<*Q*F^" ascii //weight: 1
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_IC_2147814658_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.IC!MTB"
        threat_id = "2147814658"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "v))YoOaYtihuA5xjfe4AQc!ne4@IyEJwP93)&D809!^$5j3cBrzgj*SC$Q4v5)!oIbX#rix6wU#*BGCK%m!M&rw6cTi>d$)tR!CmM9*%@0v<DKpPxOe" ascii //weight: 1
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_ID_2147814731_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.ID!MTB"
        threat_id = "2147814731"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 08 0f b6 04 02 8b 55 0c 0f b6 0c 0a 33 c8 8b 55 f4 03 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 8b 45 0c 88 0c 10 e9}  //weight: 1, accuracy: Low
        $x_1_2 = "TN^9B!24UUJJNm7e1pVYwcLh12ffZ9iKAy*Tf+7H5_^96GacV" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_IE_2147814732_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.IE!MTB"
        threat_id = "2147814732"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b ca 2b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 03 ca 2b 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 8b 55 08 0f b6 0c 0a 8b 55 0c 0f b6 04 02 33 c1 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 8b 15}  //weight: 1, accuracy: Low
        $x_1_2 = "ev4L1Ub(ydNzb2xS73IXl>I*%NF#O7eSC^" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_IF_2147814733_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.IF!MTB"
        threat_id = "2147814733"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f be 1c 29 8b 44 24 20 0f b6 04 08 03 da 03 c3 33 d2 bb ?? ?? ?? ?? f7 f3 8b 44 24 18 8a 00 8b 5c 24 34 88 44 24 13 8b c2 2b c6 8a 04 18 8b 5c 24 2c 88 04 0f 8a 44 24 12 02 44 24 13 41 ff 44 24 18 88 04 13}  //weight: 1, accuracy: Low
        $x_1_2 = "sVHVE9>PNfMnyMK5i%(lF5rnchI<dQ<LivVrdzTU*Fz4(LEx3m0q8YLIWM$L#GGvpt%kZ6aCJr9eGSVQwz<^)u54dG65Si" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_IG_2147814734_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.IG!MTB"
        threat_id = "2147814734"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b c2 2b 05 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 2b c2 03 05 ?? ?? ?? ?? 8b 55 08 0f b6 04 02 8b 55 0c 0f b6 0c 0a 33 c8 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? a1}  //weight: 1, accuracy: Low
        $x_1_2 = "k+$6yLFBxp2&Xo4WutzmT!4IXprjTu$>2+JQGF&N!97#i3%A<" ascii //weight: 1
        $x_1_3 = "sesArLg(0UDX4PyWPy(EQ8VtJka4<9ZU$>HI%54?@Tf+BbF_)YW*!sVMvM4ya%7bCGkqBgHM&7Ir?I*4YucMR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_IH_2147814884_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.IH!MTB"
        threat_id = "2147814884"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 2c 0b 8b 44 24 28 0f be 04 08 03 ea 03 c5 99 8b ef f7 fd 8a 04 0e 8b 6c 24 18 88 44 24 13 8b 44 24 20 89 5c 24 2c 8a 5c 24 13 41 ff 44 24 18 3b cf 8a 04 10 88 45 00 8b 44 24 30 88 1c 10}  //weight: 1, accuracy: High
        $x_1_2 = "3b_4^w?%qukDduR0P&LVwpzV^(b7#o1zbb?<>(!x?6l4iQT9zW0c158bsTrC>cM$&IA?qWxBfzUoT^INdB$o" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_II_2147814885_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.II!MTB"
        threat_id = "2147814885"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 54 24 28 bf ?? ?? ?? ?? 8b 44 24 24 0f be 1c 08 8b 44 24 20 0f b6 04 08 03 da 03 c3 99 8b df f7 fb 8b 5c 24 2c 8b 44 24 1c 8a 04 08 8a 1c 13 88 1c 0e 8b 5c 24 30 41 3b cf 88 04 13}  //weight: 1, accuracy: Low
        $x_1_2 = "5maS7Z0Zx!z6mJy5ff#)@$*3?0qEq3(vABIRqeHB!3CPl4XjCTtXQ_2GkaB>qSb*HOD(@4eLQZf_BNRlpfwg7U1@hE6" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_IJ_2147814911_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.IJ!MTB"
        threat_id = "2147814911"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Z!gQwtsNwaXD+dj5g0jwvTt01pP9&K@%ZHyAK*F0qX^zXT8(Ex4tEFY)by9!Vv<&kB63hJN2@m$tp6fVgKrLfkn9yF^Qs&SeibNzJgsrQ" ascii //weight: 1
        $x_1_2 = "G^6nN^?BKfD9_0XUjb!5QJ9k78)PGRu*+bw+@*R$mv6?1>sCL+e*G8qCv3QyMaD3Qa4KD6cy8L85*Z$n72igEhZ*mPH0TcVTf#Sg^zy475GuHsbn" ascii //weight: 1
        $x_1_3 = "UGJOP#hE(x&C$rkP1NLx4Fx6b!NLz&RlmG>2HffT7@yShn$&YA+U!98E#h3Ej4!0W2+rN10p5td+&FiaV" ascii //weight: 1
        $x_1_4 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_IK_2147814993_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.IK!MTB"
        threat_id = "2147814993"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 d1 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 2b d1 03 15 ?? ?? ?? ?? 8b 4d 08 0f b6 14 11 8b 4d 0c 0f b6 04 01 33 c2 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 0f af 35}  //weight: 1, accuracy: Low
        $x_1_2 = "aR<G+Kb)f)GXcqX)#IOa4Ncs71&>Q6?X>dI89@BB>Dpck&$?0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_IL_2147814994_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.IL!MTB"
        threat_id = "2147814994"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c8 03 0d ?? ?? ?? ?? 03 0d ?? ?? ?? ?? a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 2b c8 a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 03 45 08 0f b6 0c 08 8b 45 0c 0f b6 14 10 33 d1 a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 8b 4d f4 2b 0d ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 03 45 0c 88 14 08}  //weight: 1, accuracy: Low
        $x_1_2 = "pfy(otl$J0y_mA1qDC2z>OpEbaVbI1e6+#pqMuj_nmG^+&&H*Fx7x$^m6_86fNyHXj$df4b>cg_%m(h0yF>%XYsQV9(x@c" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_IM_2147814995_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.IM!MTB"
        threat_id = "2147814995"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b c8 03 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 03 c8 a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 03 45 08 0f b6 0c 08 8b 45 0c 0f b6 14 10 33 d1 a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 8b 0d}  //weight: 1, accuracy: Low
        $x_1_2 = "PiifGW%Ea73r3i)oeuJqEqON_+3RxH)e2Mkr2R!_mk4GFD6Mm+XF_" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_IN_2147815011_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.IN!MTB"
        threat_id = "2147815011"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@2^zD<BiE%mOVqm<6ol(G6^rxScUiJJ2UR?uRwT7A(M6QfSoS$N_seRke&pG&)4gvol&C7" ascii //weight: 1
        $x_1_2 = "323Ym%IM5llnOa@!FiDntscflHO*8z_32xZ&vBFIY>@<q3y" ascii //weight: 1
        $x_1_3 = "vfnRR#7fRtc<td4?U*Xh4zjKXEZ688YdW>L0F)3v>DkWWcU@" ascii //weight: 1
        $x_1_4 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_IO_2147815093_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.IO!MTB"
        threat_id = "2147815093"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 14 1a 03 c2 99 bd ?? ?? ?? ?? f7 fd 8b 44 24 58 8b 6c 24 1c 83 c5 01 89 6c 24 1c 03 54 24 4c 03 d7 03 54 24 50 0f b6 14 02 8b 44 24 18 30 54 28 ff}  //weight: 1, accuracy: Low
        $x_1_2 = "#$IDy>DBhCBJT@26$B_PO!!J1)2vM5Mfz(31yPL@*Mr&T(msVAs9YB^GT8xB<Ba*+dyJ_@(Q*tfyDv&PeW$3N&o9Aj*^)DhD_!JHo#^" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_IP_2147815094_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.IP!MTB"
        threat_id = "2147815094"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 04 28 03 c2 99 bd ?? ?? ?? ?? f7 fd 8b 44 24 58 8b 6c 24 14 83 c5 01 89 6c 24 14 2b 54 24 18 2b d1 03 54 24 4c 03 54 24 50 03 d7 0f b6 14 02 8b 44 24 10 30 54 28 ff}  //weight: 1, accuracy: Low
        $x_1_2 = "U&Scloo2aC6RnJw13JBiDOctjtrRZYnEyrPU+U^pA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_IQ_2147815096_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.IQ!MTB"
        threat_id = "2147815096"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MSmr0)P_i0DHV0RjURldysFRNP9>aKHdu7#lLY#hGlWuDV>^jjo!4R+Ep6Sdn@yN#H@m!aAV*CIRw?)" ascii //weight: 1
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_IR_2147815292_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.IR!MTB"
        threat_id = "2147815292"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "DllRegisterServer" ascii //weight: 10
        $x_1_2 = "^Alwe$f6YafqAQ1RFl7cdF7O5p0Dg?vI&t" ascii //weight: 1
        $x_1_3 = "LtaL0P1KoG<Waf1py@K3xUshlIkLN7<&%" ascii //weight: 1
        $x_1_4 = "EV&nm%guKWX>p%G?LmfaA?7(hw_9V<&lK^#wq?Oy5O" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotetcrypt_IS_2147815401_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.IS!MTB"
        threat_id = "2147815401"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "DllRegisterServer" ascii //weight: 10
        $x_1_2 = ">thaw5g+xap^jFH4nUlCwij5Z7zxMgIrh2o*Za%Tf?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_IT_2147815478_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.IT!MTB"
        threat_id = "2147815478"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "DllRegisterServer" ascii //weight: 10
        $x_1_2 = "mEy6LqoYT!_fW$op#k1WvL_6t+e3Mrqf)<TD" ascii //weight: 1
        $x_1_3 = "uSic%m4vMZ_KN6zHZ2o#*z^i<EI?n#Ngs*mqanuklDOYojIpqRgOjQh4!8TPS1ZjSQ" ascii //weight: 1
        $x_1_4 = "%!cx*kxb?_t%E0_WrTfiao+Un#k&Wp^Omj<@A_Z(rcF8vj4QUr" ascii //weight: 1
        $x_1_5 = "KGvNsd(v&CkE!FF%y4zX$269GCxIwcHSmTkL(Dl!J*es>bLoL2WAJ?L" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotetcrypt_IU_2147815560_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.IU!MTB"
        threat_id = "2147815560"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "DllRegisterServer" ascii //weight: 10
        $x_1_2 = "oNenAAabcbzZCj1(akB<tRe6H>zGl7nGrF7V8IkOOKxI" ascii //weight: 1
        $x_1_3 = "MOS&4(M4c)HG(1Gbc#xOljJ)5l_L!M?q7!CX?%X5aq$(3U8Y7liA9L%Dna%#+p8?O%naS_shLnpu8ulJqQs<h^T$AMvteCW99aQH9iQyhUO5Ovb7tLDR_g3" ascii //weight: 1
        $x_1_4 = "5HzyxhUf5EkmMtb2OKQg1cB@MUi)aIoZGVGBv<ECA9t$lOy13XFPsP<ARYLC#JCAO7?82U6pgcnar7hVcIA2Wp+wU3frThm&js!kaoQRU?1bP?" ascii //weight: 1
        $x_1_5 = "mAO*M>qkO>C&_fF)*UhE?aSnil%TE&womJirB91jzqW9BSh)u(nY#FK44H4GYc3Bk0N)KEWi&9ql#pgF6uL)E1kM39BsPcs@uR2_>>5e2g)gfLbhfdI#Yjt" ascii //weight: 1
        $x_1_6 = "u90^1GLIc^DD2Wb&Fg(HzV*5<nk@eqUek4*>z2jPG1ph54&lMxJ0c2n1Azs(b&6Log<$8V%vrEW$3J55#(<UxN07F94<?8<^?Mrf49#>EQ41<1F^" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotetcrypt_IV_2147815642_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.IV!MTB"
        threat_id = "2147815642"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "DllRegisterServer" ascii //weight: 10
        $x_1_2 = "<BGssN2^adk!>?jgH+Vnd!<Xqt>DoecEw?LQMcGgsZoyADJyZkU" ascii //weight: 1
        $x_1_3 = "u+OUr@Gnw7WU8wvzF2sdn!scsb&WO4vzuGAs+!StYXj!by7msWucK*_MI_o)m(" ascii //weight: 1
        $x_1_4 = ")H+!CBdeENM2TVMpEut@im!Ece6G9*jOJ@h*2L9CBx)NK@V" ascii //weight: 1
        $x_1_5 = "n$U<Q3qi0L2X!WL!bjvlLEQK_JDN<Q)hKy!vF6MazhubC>sJZ@<sIg5#Rff)cd$jFhSU^Tz@V(foT%Aaw(LiItz!_k1Je3HOA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotetcrypt_IW_2147815721_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.IW!MTB"
        threat_id = "2147815721"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "DllRegisterServer" ascii //weight: 10
        $x_1_2 = "8nGA7ohfFpugG(l$!#2u__*t5EaFD77" ascii //weight: 1
        $x_1_3 = "FLT8@d#PmtmV>wm%zwx%K>&*X?ZpIrrummcLvM#QBLulq4fOMO&I1NiRXoW*l&HnBGe(2@E6kO)x6V%QX4dfw@ez@<r^^$*nmZaKE_18*RMITix" ascii //weight: 1
        $x_1_4 = "w!SleU++QhBmrFJ9SJ_RC^fO)2UxN5MlNF9S)g00ffH27*ixEFK*X&%K^@elV8LtI%PCk2o*1R+c6*tx2H>f1E3gvfuO>+mF7rnN7_tXjfxkVgFb" ascii //weight: 1
        $x_1_5 = "NF*0%*F&PYU5D%V9U95IUUEULekAEq3Pu5RqsL?trX3nqllo^cOx4B+9FZlBRW1nyLkdCsMgQU7I>?QhmoVV8+FY)cGeoWD7iQWK5P" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotetcrypt_IX_2147815801_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.IX!MTB"
        threat_id = "2147815801"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "DllRegisterServer" ascii //weight: 10
        $x_1_2 = "4xesk_xgwn1kSwV3MF125u2n#b6uVJlH" ascii //weight: 1
        $x_1_3 = "x5Dn%GGoY)l^^W5FNvtpBJs4%N?oGU<XC<RcoXJ<cGP#P)I>GM4^6Yt1_o9nt*+PGXoJWJ4c2ef%hwDz1nNH#&)b$(thJvk6eAn3NoB(+9+C*YxC" ascii //weight: 1
        $x_1_4 = "m(WIRBcKc$sXZ7Ii0foV1j6ffy<2hE1m94txsO?7)GI*@iZw(kycXS$>*AB8!6QKfd#BohWTtLxJ66^&Rz$S7y+cK5DN2ob4" ascii //weight: 1
        $x_1_5 = "e?ExvYi<2#ILb?1jpvSJnYvHw46QgTU$E)!8lHU<#YFose8B+OYHzZw6!zl0rzFW8JxWw3q)K_lg15Fk4nI^Q9ig1eNxf^mjlP+!jZmMUmdpXlZ" ascii //weight: 1
        $x_1_6 = "Fny&Tw8gY0rMdnT$?qd4TW8dJ2V9@5^0KLxm$&81!Zizfd>OAq>wxq3NsvmRMa%LL9rHIhi8eS6c@_d8Xwp%vIrp&v+P(3ZIuL&66Eu^&KB3Npa*" ascii //weight: 1
        $x_1_7 = "mNBl(v1EacG7SZ?tMEm6G_g^iRZl9AasuIg?e3htGkV+0j" ascii //weight: 1
        $x_1_8 = "y6o)UW(j(tIn4B2o??@??h6spHYC9g@VS+" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotetcrypt_IY_2147816066_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.IY!MTB"
        threat_id = "2147816066"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "DllRegisterServer" ascii //weight: 10
        $x_1_2 = "))a2IvxVNc!@ny+eaNOA3$+*M5Aa<%btD0cCdIrH)2_0<1fkgx#4^S8yrehZ$<N)m3ds7vfJo&WmQQ@)h$Uoyyb0vqdxu%*4$Q" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_IZ_2147816218_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.IZ!MTB"
        threat_id = "2147816218"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f af d6 0f af 15 ?? ?? ?? ?? 8b 2d ?? ?? ?? ?? 03 e9 8d 4c 6a 02 0f af 0d ?? ?? ?? ?? 2b d9 48 0f af c6 03 fb 8b 4c 24 48 8a 14 38 8b 44 24 28 8a 18 32 da 88 18}  //weight: 1, accuracy: Low
        $x_1_2 = "SFnFxoMA8e2R&_^nrEAWsVhlxQS9P&D*D%>eYngNdsGx4@e0HEC#b9YvE$)1gmkXh^BNu0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_JA_2147816289_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.JA!MTB"
        threat_id = "2147816289"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 2c 83 c0 02 0f af c7 6b c0 03 03 d0 8d 41 03 0f af 05 ?? ?? ?? ?? 03 44 24 5c 2b d6 8b 74 24 44 0f af f1 03 c2 8a 0c 06 8b 44 24 48 30 08}  //weight: 1, accuracy: Low
        $x_1_2 = "owN>%@+EJXR4$Px#PzJXyzQZK2F^*qj*KxGk!^M1pXNHNq" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_JB_2147816297_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.JB!MTB"
        threat_id = "2147816297"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 0c 00 2b d9 0f af d8 b8 01 00 00 00 03 d3 2b c5 0f af 05 ?? ?? ?? ?? 8d 4c 00 05 8b 44 24 30 0f af 0d ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 03 ce 03 ca 8a 0c 08 8b 44 24 2c 8a 18 32 d9 88 18}  //weight: 1, accuracy: Low
        $x_1_2 = "s_)x7#4VF+Ur_kc%rX^r6#oU*(@q#?6*Z6R9_lZT3bTZv8W9*FU?ZOS6fw^i^1QJLGw56u" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_JC_2147816374_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.JC!MTB"
        threat_id = "2147816374"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ea 0f af e9 2b dd 2b d8 2b d8 2b d8 2b d8 8b 44 24 ?? 2b de 2b d9 2b d9 2b d9 2b d9 03 df 03 df 8a 0c 03 8b 44 24 ?? 8a 18 32 d9 8b 4c 24 ?? 88 18}  //weight: 1, accuracy: Low
        $x_1_2 = "fF4boAAq3xmQAiQ!Ac8&6eQEi4!nIQ(2ihQ^<sCK0%t_bJ*H?vG" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_JD_2147816517_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.JD!MTB"
        threat_id = "2147816517"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f af d7 2b d0 a1 ?? ?? ?? ?? 2b d0 42 0f af 15 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 c9 2b d1 8b 0d ?? ?? ?? ?? 2b d1 8b 4c 24 30 03 d0 8a 45 00 03 d1 8b 4c 24 3c 8a 14 1a 32 c2 88 45 00}  //weight: 1, accuracy: Low
        $x_1_2 = "X@i(O5SN3VnP?A6_fr^VY+@R_m9$<Fu4pN_H#yGMvQ)5FUVi164^^1$zmumE1Fz" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_JE_2147816669_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.JE!MTB"
        threat_id = "2147816669"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "DllRegisterServer" ascii //weight: 10
        $x_1_2 = "zTssa?%<ti6Q@Aa?bE+o6bi1WPpBhSWprcy3" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_JF_2147816734_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.JF!MTB"
        threat_id = "2147816734"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 fc 83 c0 01 89 45 fc 8b 4d fc 3b 4d 10 73 ?? 8b 55 08 03 55 fc 0f b6 0a 8b 45 fc 33 d2 f7 75 18 8b 45 14 0f b6 14 10 33 ca 8b 45 0c 03 45 fc 88 08 eb}  //weight: 1, accuracy: Low
        $x_1_2 = "flickr" ascii //weight: 1
        $x_2_3 = "Vg7M+JJb0D5OD8E(To<(B%#3U9JDiejzY>ToNUehD" ascii //weight: 2
        $x_10_4 = "DllRegisterServer" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotetcrypt_JG_2147816775_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.JG!MTB"
        threat_id = "2147816775"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "DllRegisterServer" ascii //weight: 10
        $x_1_2 = "w!SleU++QhBmrFJ9SJ_RC^fO)2UxN5MlNF9S)g00ffH27*ixEFK*X&%K^@elV8LtI%PCk2o*1R+c6*tx2H>f1E3gvfuO>+mF7rnN7_tXjfxkVgFb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_SA_2147817045_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.SA!MTB"
        threat_id = "2147817045"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b d0 03 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 2b d0 8b 45 14 0f b6 14 10 33 ca}  //weight: 1, accuracy: Low
        $x_1_2 = {03 45 0c 88 0c 10 e9 15 00 0f af 05 ?? ?? ?? ?? 2b d0 a1 ?? ?? ?? ?? 0f af 05}  //weight: 1, accuracy: Low
        $x_1_3 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_JI_2147817047_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.JI!MTB"
        threat_id = "2147817047"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "DllRegisterServer" ascii //weight: 10
        $x_1_2 = "XhYv9oU7nQ3(qEqm>*SUB^vCkf^x8c^bNvy9sJY@LrovC1+OPTPpl6R+<" ascii //weight: 1
        $x_1_3 = "bWU6YFCCc8(7fyvz3ia<fm&I752lWU+LUO_Qu$gNyaPPIeR7OBzG5bCNgHaHhYge9kd$j<U" ascii //weight: 1
        $x_1_4 = "2ZTYXG7K5#RY+(uRRaE&LXIvF!+@>m779sEjBU)d(Mb3_!Z" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emotetcrypt_JH_2147817060_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.JH!MTB"
        threat_id = "2147817060"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e0 a5 a7 0f d7 03 11 a2 31 a4 33 b0 e8 ca 8d 53 f6 f1 91 01 7d f3 73 0a b4 b1 c8 0a f0 1b c8 cf d3 74 c5 2b 28 e7 55 58 2d 96 1e 00 5d 43 89 e6 df a5 26 b0 bd 4a c0 55 e7 e7 26 79 3d 4c 4e c8}  //weight: 1, accuracy: High
        $x_1_2 = "Macros.dll" ascii //weight: 1
        $x_1_3 = "DllRegisterServer" ascii //weight: 1
        $x_1_4 = "DllUnregisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_JJ_2147817077_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.JJ!MTB"
        threat_id = "2147817077"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 d0 2b 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 2b 15 ?? ?? ?? ?? 8b 45 14 0f b6 14 10 33 ca a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 03 45 fc 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 2b c2 03 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 03 c2}  //weight: 1, accuracy: Low
        $x_1_2 = "X4RPT3BM&wBYRKzjRT0NLpX?#cAoY*YVRnBPYWT66m1fpj?6ySW0pK_Y2fUAX5$" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_JL_2147817149_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.JL!MTB"
        threat_id = "2147817149"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MTGestures.dll" ascii //weight: 1
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
        $x_1_3 = "zA)9$1Vu<yx@#YLjP0p(#%P>PJx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_JP_2147817356_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.JP!MTB"
        threat_id = "2147817356"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "AlphaBlend" ascii //weight: 10
        $x_1_2 = "Fxyvodanywek" ascii //weight: 1
        $x_1_3 = "Cqohyzidimip" ascii //weight: 1
        $x_1_4 = "Nzyhenuzimecy" ascii //weight: 1
        $x_1_5 = "Qmyramowuk" ascii //weight: 1
        $x_1_6 = "Mnuwadifej" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_KH_2147819284_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.KH!MTB"
        threat_id = "2147819284"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b d0 2b 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 03 d0 a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 2b d0 a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 03 c2 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 03 55 14 0f b6 04 02 33 c8 8b 55 fc 2b 15 ?? ?? ?? ?? 2b 15 ?? ?? ?? ?? 2b 15 ?? ?? ?? ?? 03 15}  //weight: 1, accuracy: Low
        $x_1_2 = "DoKU78&5^MQ&waaq$800rRAdp2a?$Z9yVZW4LEDns8JoqpTj($H&X(*UmPOaIVARp!q92f2p4)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Emotetcrypt_YAA_2147914862_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.YAA!MTB"
        threat_id = "2147914862"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 04 35 ?? ?? ?? ?? c7 44 24 44 00 00 00 00 c7 44 24 40 00 00 00 00 8b 4c 24 10 8a 3c 11 28 df 8b 54 24 1c 88 7c 24 23}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_YAB_2147914950_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.YAB!MTB"
        threat_id = "2147914950"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 74 24 04 f7 f6 8a 1c 15 b2 11 40 00 8b 54 24 18 8a 3c 0a 28 df 8b 7c 24 14 88 3c 0f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emotetcrypt_YAC_2147914951_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emotetcrypt.YAC!MTB"
        threat_id = "2147914951"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emotetcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 f6 89 74 24 54 89 44 24 50 8b 44 24 40 8a 34 08 30 d6 c6 44 24 5f 80 8a 54 24 3b 80 e2 4a 88 54 24 5f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

