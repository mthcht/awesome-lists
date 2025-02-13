rule Trojan_Win32_SpySnake_MI_2147811460_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpySnake.MI!MTB"
        threat_id = "2147811460"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "qwgftllm.dll" ascii //weight: 1
        $x_1_2 = "znvaul" ascii //weight: 1
        $x_1_3 = "TEMP\\nsi28A9.tmp" ascii //weight: 1
        $x_1_4 = "creation\\snatch\\intimacy" ascii //weight: 1
        $x_1_5 = "SOFTWARE\\reaches\\cobra" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SpySnake_ML_2147834888_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpySnake.ML!MTB"
        threat_id = "2147834888"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 ff 8d 85 e4 fe ff ff 57 68 80 00 00 00 6a 03 57 6a 01 68 00 00 00 80 50 ff 15}  //weight: 10, accuracy: High
        $x_10_2 = {8b f0 57 56 ff 15 ?? ?? ?? ?? 6a 40 8b d8 68 00 30 00 00 53 57 89 5d fc ff 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SpySnake_MM_2147835330_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpySnake.MM!MTB"
        threat_id = "2147835330"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {88 45 ff 0f b6 4d ff c1 f9 ?? 0f b6 55 ff c1 e2 ?? 0b ca 88 4d ff 0f b6 45 ff 33 45 f4 88 45 ff 0f b6 4d ff 81 e9 ?? ?? ?? ?? 88 4d ff 8b 55 ec 03 55 f4 8a 45 ff 88 02 e9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SpySnake_MN_2147835732_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpySnake.MN!MTB"
        threat_id = "2147835732"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {53 56 57 6a 00 68 80 00 00 00 6a 03 6a 00 6a 01 89 45 b0 8b 45 10 68 00 00 00 80 50 ff 15}  //weight: 10, accuracy: High
        $x_5_2 = {6a 00 8b f8 8d 45 f8 50 53 57 56 ff 15 60 01 41 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SpySnake_MK_2147835824_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpySnake.MK!MTB"
        threat_id = "2147835824"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {6a 00 68 80 00 00 00 6a 03 6a 00 6a 01 68 00 00 00 80 8d 85 ac fd ff ff 50 ff 55}  //weight: 10, accuracy: High
        $x_10_2 = {89 45 f4 6a 00 8d 45 d4 50 8b 4d e8 51 8b 55 f4 52 8b 45 ec 50 ff 15}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SpySnake_MO_2147836374_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpySnake.MO!MTB"
        threat_id = "2147836374"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {83 c4 0c 6a 00 68 80 00 00 00 6a 03 6a 00 6a 01 68 00 00 00 80 b9 04 00 00 00 c1 e1 00 8b 55 0c 8b 04 0a 50 ff 15}  //weight: 10, accuracy: High
        $x_5_2 = {89 45 f8 6a 00 8d 85 44 ff ff ff 50 8b 4d 94 51 8b 55 f8 52 8b 45 8c 50 ff 15}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SpySnake_MP_2147837524_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpySnake.MP!MTB"
        threat_id = "2147837524"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8a 04 39 2c 5c 34 99 2c 23 34 ed 04 3a 34 aa fe c8 88 04 39 47 3b fb 72}  //weight: 5, accuracy: High
        $x_5_2 = {51 68 80 00 00 00 6a 03 51 6a 01 68 00 00 00 80 ff 75 10 ff 15}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SpySnake_MQ_2147837857_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpySnake.MQ!MTB"
        threat_id = "2147837857"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8a 04 37 34 76 04 7b 34 f2 2c 23 34 8e 04 42 34 d7 fe c0 88 04 37 46 3b f3 72}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SpySnake_MR_2147837858_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpySnake.MR!MTB"
        threat_id = "2147837858"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {ff d7 8b 55 10 6a 00 8d 4d fc 51 53 8b f8 57 52 ff 15 94 d0 40}  //weight: 5, accuracy: High
        $x_3_2 = {8a 04 37 2c 60 34 af 2c 53 34 bd 04 52 88 04 37 46 3b f3 72 ?? 6a 00 6a 00 6a 02 57 ff 15}  //weight: 3, accuracy: Low
        $x_3_3 = {8a 04 37 2c 45 34 8e fe c8 34 fd 04 73 88 04 37 46 3b f3 72 ?? 6a 00 6a 00 6a 02 57 ff 15}  //weight: 3, accuracy: Low
        $x_3_4 = {8a 04 37 2c 52 34 b8 2c 31 34 f4 2c 45 34 1f fe c0 34 ba fe c0 88 04 37 46 3b f3 72 ?? 6a 00 6a 00 6a 02 57 ff 15}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_3_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_SpySnake_MS_2147837859_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpySnake.MS!MTB"
        threat_id = "2147837859"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 04 37 04 07 34 75 fe c8 88 04 37 46 3b f3 72 ?? 6a 00 6a 00 6a 02 57 ff 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SpySnake_2147840571_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpySnake.MT!MTB"
        threat_id = "2147840571"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpySnake"
        severity = "Critical"
        info = "MT: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {b8 ab aa aa aa f7 e1 c1 ea 03 8d 14 52 03 d2 03 d2 8b c1 2b c2 8a ?? ?? ?? ?? ?? 30 14 0b 41 3b ce 72}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SpySnake_MU_2147840672_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpySnake.MU!MTB"
        threat_id = "2147840672"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {bf ab aa aa aa 0f 1f 80 00 00 00 00 89 c8 f7 e7 d1 ea 83 e2 fc 8d 04 52 89 ca 29 c2 0f b6 92 a2 da 41 00 30 14 0e f7 d8 0f b6 84 01 a3 da 41 00 30 44 0e 01 83 c1 02 39 cb 75}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SpySnake_MV_2147840816_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpySnake.MV!MTB"
        threat_id = "2147840816"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {33 c0 83 c4 10 8b c8 85 f6 74 1b 8b c1 99 c7 45 c8 0c 00 00 00 f7 7d c8 8a 82 08 e5 40 00 30 04 0b 41 3b ce 72 e5}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SpySnake_MW_2147840817_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpySnake.MW!MTB"
        threat_id = "2147840817"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {83 c4 10 33 c9 85 db 74 16 8b c1 99 6a 0c 5e f7 fe 8a 82 70 d6 40 00 30 04 0f 41 3b cb 72 ea}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SpySnake_MJ_2147900099_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpySnake.MJ!MTB"
        threat_id = "2147900099"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpySnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 45 f4 03 45 f8 8a 08 88 4d ff 0f b6 55 ff 83 ea 7b 88 55 ff 0f b6 45 ff 35 a4 00 00 00 88 45 ff 0f b6 4d ff}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

