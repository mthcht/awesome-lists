rule Trojan_Win32_REntS_SIBB_2147780093_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/REntS.SIBB!MTB"
        threat_id = "2147780093"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "REntS"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {52 68 00 10 00 00 8d 85 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 85 c0 74 ?? 8b 85 ?? ?? ?? ?? c1 e8 02 33 db 89 85 ?? ?? ?? ?? 85 c0 74 ?? 8d 49 00 68 ?? ?? ?? ?? 8d 8d ?? ?? ?? ?? 6a 00 51 e8 ?? ?? ?? ?? 8b 84 9d 00 83 c4 0c 50 33 ff 57 68 10 04 00 00 ff 15 ?? ?? ?? ?? 8b f0 85 f6 74 ?? 68 ?? ?? ?? ?? 8d 95 07 52 56 ff 15 ?? ?? ?? ?? 85 c0 74 ?? bf 01 00 00 00 56 ff 15 ?? ?? ?? ?? 85 ff 74 ?? 8d 85 07 8d 50 01 8a 08 40 84 c9 75 ?? 2b c2 83 f8 ?? 7c ?? 8d 84 05 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 83 c4 08 85 c0 74 ?? 43 3b 9d 04 0f 82 ?? ?? ?? ?? e9 ?? ?? ?? ?? 8b 4d ?? 8b 84 9d 00 5f 5e 33 cd}  //weight: 10, accuracy: Low
        $x_10_2 = {2e 63 6e 2f [0-10] 2e 69 6e 69}  //weight: 10, accuracy: Low
        $x_1_3 = {53 6f 66 74 77 61 72 65 5c [0-8] 4d 61 72 6b}  //weight: 1, accuracy: Low
        $x_1_4 = "\\Windows\\explorer.exe" ascii //weight: 1
        $x_1_5 = "SeDebugPrivilege" ascii //weight: 1
        $x_1_6 = "IsNetworkAlive" ascii //weight: 1
        $x_1_7 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_REntS_SIB_2147808570_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/REntS.SIB!MTB"
        threat_id = "2147808570"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "REntS"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "<program name unknown>" wide //weight: 1
        $x_1_2 = {0f b6 00 0f b6 4c 24 ?? 33 c1 48 8b 8c 24 ?? ?? ?? ?? 48 8b 54 24 ?? 48 2b d1 48 8b ca 0f b6 c9 81 e1 ?? ?? ?? ?? 33 c1 48 8b 4c 24 02 88 01}  //weight: 1, accuracy: Low
        $x_1_3 = {0f be 04 01 35 ?? ?? ?? ?? 88 44 24 ?? 48 63 44 24 ?? 48 8b 8c 24 ?? ?? ?? ?? 48 03 c8 48 8b c1 48 89 44 24 ?? 48 83 7c 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_REntS_SIB_2147808570_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/REntS.SIB!MTB"
        threat_id = "2147808570"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "REntS"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "<Module>{668A4953-198C-4184-A9DF-E2841BA5A779}" ascii //weight: 1
        $x_1_2 = {0f b6 08 0f b6 50 01 80 f1 ?? 80 f2 ?? 88 4c 24 ?? 0f b6 48 02 88 54 24 ?? 0f b6 50 03 f6 d1 80 f2 ?? 88 4c 24 ?? 0f b6 48 04 88 54 24 ?? 0f b6 50 05 80 f1 ?? 80 f2 ?? 88 4c 24 ?? 0f b6 48 06 88 54 24 ?? 0f b6 50 07 80 f1 ?? 80 f2 ?? 88 4c 24 ?? 0f b6 48 08 88 54 24 ?? 0f b6 50 09 80 f1 ?? 80 f2 ?? 88 4c 24 ?? 0f b6 48 0a 88 54 24 ?? 0f b6 50 0b 80 f1 ?? 80 f2 ?? 88 4c 24 ?? 0f b6 48 0c 88 54 24}  //weight: 1, accuracy: Low
        $x_1_3 = {8d 04 0b 83 c8 ?? bb ?? ?? ?? ?? 0f b6 6c 14 ?? 99 f7 fb 0f b6 44 14 02 0f af c5 8b d7 81 e2 ff 00 00 00 c1 e2 ?? 03 d5 0f b6 14 32 03 c7 33 c2 25 ff 00 00 80 79 ?? 48 0d 00 ff ff ff 40 88 01 8b 44 24 ?? 99 f7 fb 8b 44 24 ?? 03 c1 83 c8 ?? bd ?? ?? ?? ?? 0f b6 5c 14 02 99 f7 fd 0f b6 54 14 02 0f af d3 8d 44 3a 01 8b 54 24 06 81 e2 ff 00 00 00 c1 e2 ?? 03 d3 0f b6 14 32 33 c2 25 ff 00 00 80 79 ?? 48 0d 00 ff ff ff 40 88 41 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_REntS_SIBQ_2147809914_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/REntS.SIBQ!MTB"
        threat_id = "2147809914"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "REntS"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "360se6\\User Data\\Default\\360Bookmarks" wide //weight: 1
        $x_1_2 = {89 18 83 c0 ?? 8a 0b 89 45 ?? 8a 43 01 2a c1 fe c9 c0 e1 ?? 0a c1 88 07 3b f2 76 ?? [0-5] 0f be 44 53 ?? 0f be 0c 53 2b c8 79 ?? 83 c1 ?? c0 e1 ?? 88 0c 3a 0f be 4c 53 ?? 0f be 04 53 2b c8 79 ?? 83 c1 ?? 80 e1 ?? 08 0c 3a 42 3b d6 7c}  //weight: 1, accuracy: Low
        $x_1_3 = {8d 76 ff 8d 04 37 8a 0c 18 88 08 30 0e 8b 45 ?? 8b 4d ?? 8a 04 30 88 04 31 80 c2 ff 75 ?? 8b 5d ?? b2 10 8a 4b ?? [0-5] 0f b6 43 ?? 88 43 ?? 0f b6 43 ?? 88 43 ?? 0f b6 43 ?? 88 43 ?? 0f b6 43 ?? 88 4b ?? 8a 4b ?? 88 43 ?? 0f b6 43 ?? 88 4b ?? 8a 4b ?? 88 43 ?? 0f b6 43 ?? 88 43 ?? 0f b6 43 ?? 88 4b ?? 8a 4b ?? 88 43 ?? 0f b6 43 ?? 88 4b ?? [0-5] 88 43}  //weight: 1, accuracy: Low
        $x_1_4 = {0f b6 04 08 8d 49 04 30 41 fc b8 ?? ff ff ff 0f b6 44 08 fc 30 44 0f fc b8 ?? ff ff ff 0f b6 44 08 fc 30 44 0b fc 83 c8 ff 0f b6 44 08 fc 30 44 0a fc b8 ?? ff ff ff 83 ee 01 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_REntS_SIBT_2147811830_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/REntS.SIBT!MTB"
        threat_id = "2147811830"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "REntS"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "pebmnqhz.dll" ascii //weight: 1
        $x_1_2 = {88 01 8b 45 ?? 03 45 ?? 8a 00 04 ?? 8b 4d 00 03 4d 01 88 01 8b 45 00 03 45 01 0f b6 00 35 ?? ?? ?? ?? 8b 4d 00 03 4d 01 88 01 8b 45 00 03 45 01 0f b6 00 05 ?? ?? ?? ?? 8b 4d 00 03 4d 01 88 01 8b 45 01 40 89 45 01 8b 45 01 3b 45 ?? 8b 45 00 ff e0}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 55 08 b9 ?? ?? ?? ?? 8a 02 84 c0 6b c9 ?? 0f be c0 03 c8 42 8a 02 84 c0 75 ?? 8b c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_REntS_SIBT1_2147811954_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/REntS.SIBT1!MTB"
        threat_id = "2147811954"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "REntS"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 00 83 e8 ?? 8b 4d ?? 03 4d ?? 88 01 8b 45 01 03 45 02 0f b6 00 83 f0 ?? 8b 4d 01 03 4d 02 88 01 8b 45 01 03 45 02 0f b6 00 83 c0 ?? 8b 4d 01 03 4d 02 88 01 8b 45 02 40 89 45 02 8b 45 02 3b 45 ?? 8b 45 01 ff e0}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 55 08 b9 ?? ?? ?? ?? 8a 02 84 c0 6b c9 ?? 0f be c0 03 c8 42 8a 02 84 c0 75 ?? 8b c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_REntS_SIBT2_2147811955_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/REntS.SIBT2!MTB"
        threat_id = "2147811955"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "REntS"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 01 8b 45 ?? 03 45 ?? 0f b6 00 83 c0 ?? 8b 4d 00 03 4d 01 88 01 8b 45 00 03 45 01 0f b6 00 2d ed 00 00 00 8b 4d 00 03 4d 01 88 01 8b 45 01 40 89 45 01 8b 45 01 3b 45 ?? 8b 45 00 ff e0}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 55 08 b9 ?? ?? ?? ?? 8a 02 84 c0 6b c9 21 0f be c0 03 c8 42 8a 02 84 c0 75 ?? 8b c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_REntS_SIBT3_2147811956_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/REntS.SIBT3!MTB"
        threat_id = "2147811956"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "REntS"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 00 35 ?? ?? ?? ?? 8b 4d ?? 03 4d ?? 88 01 8b 45 01 03 45 02 8a 00 04 01 8b 4d 01 03 4d 02 88 01 8b 45 01 03 45 02 8a 00 04 01 8b 4d 01 03 4d 02 88 01}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 55 08 b9 ?? ?? ?? ?? 8a 02 84 c0 6b c9 ?? 0f be c0 03 c8 42 8a 02 84 c0 75 ?? 8b c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_REntS_SIBT4_2147812048_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/REntS.SIBT4!MTB"
        threat_id = "2147812048"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "REntS"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 00 83 f0 ?? 8b 4d ?? 03 4d ?? 88 01 8b 45 01 03 45 02 0f b6 00 2d f2 00 00 00 8b 4d 01 03 4d 02 88 01 8b 45 01 03 45 02 8a 00 04 01 8b 4d 01 03 4d 02 88 01 8b 45 01 03 45 02 8a 00 04 01 8b 4d 01 03 4d 02 88 01}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 55 08 b9 3a b6 01 00 8a 02 84 c0 6b c9 ?? 0f be c0 03 c8 42 8a 02 84 c0 75 ?? 8b c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_REntS_SIBT5_2147812049_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/REntS.SIBT5!MTB"
        threat_id = "2147812049"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "REntS"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 00 83 f0 ?? 8b 4d ?? 03 4d ?? 88 01 8b 45 01 03 45 02 8a 00 2c ?? 8b 4d 01 03 4d 02 88 01 8b 45 01 03 45 02 0f b6 00 05 ?? ?? ?? ?? 8b 4d 01 03 4d 02 88 01 8b 45 01 03 45 02 8a 00 04 ?? 8b 4d 01 03 4d 02 88 01}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 55 08 b9 3a b6 01 00 8a 02 84 c0 6b c9 ?? 0f be c0 03 c8 42 8a 02 84 c0 75 ?? 8b c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_REntS_SIBT6_2147812262_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/REntS.SIBT6!MTB"
        threat_id = "2147812262"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "REntS"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 00 83 f0 ?? 8b 4d ?? 03 4d ?? 88 01}  //weight: 10, accuracy: Low
        $x_10_2 = {88 01 8b 45 ?? 03 45 ?? 0f b6 00 83 c0 ?? 8b 4d 00 03 4d 01 88 01}  //weight: 10, accuracy: Low
        $x_10_3 = {88 01 8b 45 ?? 03 45 ?? 8a 00 2c ?? 8b 4d 00 03 4d 01 88 01}  //weight: 10, accuracy: Low
        $x_1_4 = {8b 55 08 b9 3a b6 01 00 8a 02 84 c0 6b c9 ?? 0f be c0 03 c8 42 8a 02 84 c0 75 ?? 8b c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_REntS_SIBT7_2147812432_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/REntS.SIBT7!MTB"
        threat_id = "2147812432"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "REntS"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {88 01 8b 45 ?? 03 45 ?? 0f b6 00 83 c0 ?? 8b 4d 00 03 4d 01 88 01}  //weight: 10, accuracy: Low
        $x_10_2 = {88 01 8b 45 ?? 03 45 ?? 8a 00 2c ?? 8b 4d 00 03 4d 01 88 01}  //weight: 10, accuracy: Low
        $x_1_3 = {8a 06 84 c0 6b ff ?? 0f be c0 03 f8 46 8a 06 84 c0 75 ?? 3b 7d ?? 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_REntS_SIBT8_2147812660_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/REntS.SIBT8!MTB"
        threat_id = "2147812660"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "REntS"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 02 05 ?? ?? ?? ?? 8b 4d ?? 03 4d ?? 88 01}  //weight: 1, accuracy: Low
        $x_1_2 = {88 0a 8b 55 ?? 03 55 ?? 8a 02 2c 01 8b 4d ?? 03 4d ?? 88 01}  //weight: 1, accuracy: Low
        $x_1_3 = {8a 1a 84 db 74 ?? 8b c8 8d 52 ?? c1 e0 ?? 03 c1 0f be cb 8a 1a 03 c1 84 db 75 ?? 8b 4d 08 3b 45 0c 74 ?? 8b 55 ?? 46 3b f1 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_REntS_SIBT9_2147812661_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/REntS.SIBT9!MTB"
        threat_id = "2147812661"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "REntS"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 34 08 89 f3 81 c3 ?? ?? ?? ?? 88 1c 08}  //weight: 1, accuracy: Low
        $x_1_2 = {88 14 08 8b 85 ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 0f b6 34 08 89 f2 83 ea ?? 88 14 08}  //weight: 1, accuracy: Low
        $x_1_3 = {88 14 08 8b 85 ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 0f b6 34 08 89 f2 81 f2 ?? ?? ?? ?? 88 14 08}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 45 08 80 38 00 0f 84 ?? ?? ?? ?? 8b 45 ?? c1 e0 ?? 03 45 01 8b 4d 08 0f be 09 01 c8 89 45 01 8b 45 08 83 c0 01 89 45 08 8b 45 08 80 38 00 8b 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_REntS_SIBT10_2147812821_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/REntS.SIBT10!MTB"
        threat_id = "2147812821"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "REntS"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 01 8b 55 ?? 03 55 ?? 8a 02 04 ?? 8b 4d 00 03 4d 01 88 01}  //weight: 1, accuracy: Low
        $x_1_2 = {88 01 8b 55 ?? 03 55 ?? 0f b6 02 2d ?? ?? ?? ?? 8b 4d 00 03 4d 01 88 01}  //weight: 1, accuracy: Low
        $x_1_3 = {88 01 8b 55 ?? 03 55 ?? 0f b6 02 35 ?? ?? ?? ?? 8b 4d 00 03 4d 01 88 01}  //weight: 1, accuracy: Low
        $x_1_4 = {8b c8 8d 52 01 c1 e0 ?? 03 c1 0f be cb 8a 1a 03 c1 84 db 75 ?? 8b 4d 08 3b 45 0c 74 13}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_REntS_SIBT11_2147812822_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/REntS.SIBT11!MTB"
        threat_id = "2147812822"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "REntS"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 10 8b 4d ?? 03 4d ?? 0f b6 11 81 c2 ?? ?? ?? ?? 8b 45 00 03 45 01 88 10}  //weight: 1, accuracy: Low
        $x_1_2 = {88 10 8b 4d ?? 03 4d ?? 8a 11 80 ea ?? 8b 45 00 03 45 01 88 10}  //weight: 1, accuracy: Low
        $x_1_3 = {88 10 8b 4d ?? 03 4d ?? 0f b6 11 83 f2 ?? 8b 45 00 03 45 01 88 10}  //weight: 1, accuracy: Low
        $x_1_4 = {8b c8 8d 52 01 c1 e0 ?? 03 c1 0f be cb 8a 1a 03 c1 84 db 75 ?? 8b 4d 08 3b 45 0c 74 13}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_REntS_SIBT12_2147812823_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/REntS.SIBT12!MTB"
        threat_id = "2147812823"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "REntS"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 10 8b 4d ?? 03 4d ?? 0f b6 11 81 f2 ?? ?? ?? ?? 8b 45 00 03 45 01 88 10}  //weight: 1, accuracy: Low
        $x_1_2 = {88 10 8b 4d ?? 03 4d ?? 0f b6 11 81 c2 ?? ?? ?? ?? 8b 45 00 03 45 01 88 10}  //weight: 1, accuracy: Low
        $x_1_3 = {88 10 8b 4d ?? 03 4d ?? 8a 11 80 ea ?? 8b 45 00 03 45 01 88 10}  //weight: 1, accuracy: Low
        $x_1_4 = {8b c8 8d 52 01 c1 e0 ?? 03 c1 0f be cb 8a 1a 03 c1 84 db 75 ?? 8b 4d 08 3b 45 0c 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_REntS_SIBT13_2147812943_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/REntS.SIBT13!MTB"
        threat_id = "2147812943"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "REntS"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 08 80 e9 ?? 8b 55 ?? 03 55 ?? 88 0a}  //weight: 1, accuracy: Low
        $x_1_2 = {88 0a 8b 45 ?? 03 45 ?? 0f b6 08 81 f1 ?? ?? ?? ?? 8b 55 00 03 55 01 88 0a}  //weight: 1, accuracy: Low
        $x_1_3 = {88 0a 8b 45 ?? 03 45 ?? 8a 08 80 c1 ?? 8b 55 00 03 55 01 88 0a}  //weight: 1, accuracy: Low
        $x_1_4 = {8b c8 8d 52 01 c1 e0 ?? 03 c1 0f be cb 8a 1a 03 c1 84 db 75 ?? 8b 4d 08 3b 45 0c 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_REntS_SIBT14_2147812944_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/REntS.SIBT14!MTB"
        threat_id = "2147812944"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "REntS"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 01 8b 55 ?? 03 55 ?? 0f b6 02 05 ?? ?? ?? ?? 8b 4d 00 03 4d 01 88 01}  //weight: 1, accuracy: Low
        $x_1_2 = {88 01 8b 55 ?? 03 55 ?? 0f b6 02 83 e8 ?? 8b 4d 00 03 4d 01 88 01}  //weight: 1, accuracy: Low
        $x_1_3 = {88 01 8b 55 ?? 03 55 ?? 0f b6 02 83 f0 ?? 8b 4d 00 03 4d 01 88 01}  //weight: 1, accuracy: Low
        $x_1_4 = {8b c8 8d 52 01 c1 e0 ?? 03 c1 0f be cb 8a 1a 03 c1 84 db 75 ?? 8b 4d 08 3b 45 0c 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_REntS_SIBT15_2147813335_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/REntS.SIBT15!MTB"
        threat_id = "2147813335"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "REntS"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 02 05 ?? ?? ?? ?? 8b 4d ?? 03 4d ?? 88 01}  //weight: 1, accuracy: Low
        $x_1_2 = {88 01 8b 55 ?? 03 55 ?? 8a 02 2c 01 8b 4d 00 03 4d 01 88 01}  //weight: 1, accuracy: Low
        $x_1_3 = {88 01 8b 55 ?? 03 55 ?? 0f b6 02 35 ?? ?? ?? ?? 8b 4d 00 03 4d 01 88 01}  //weight: 1, accuracy: Low
        $x_1_4 = {0f be 11 85 d2 74 ?? 8b 45 ?? c1 e0 ?? 03 45 01 8b 4d 08 0f be 11 03 c2 89 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_REntS_SIBT16_2147813336_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/REntS.SIBT16!MTB"
        threat_id = "2147813336"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "REntS"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 01 8b 55 ?? 03 55 ?? 0f b6 02 83 c0 ?? 8b 4d 00 03 4d 01 88 01}  //weight: 1, accuracy: Low
        $x_1_2 = {88 01 8b 55 ?? 03 55 ?? 0f b6 02 2d ?? ?? ?? ?? 8b 4d 00 03 4d 01 88 01}  //weight: 1, accuracy: Low
        $x_1_3 = {88 01 8b 55 ?? 03 55 ?? 0f b6 02 35 ?? ?? ?? ?? 8b 4d 00 03 4d 01 88 01}  //weight: 1, accuracy: Low
        $x_1_4 = {0f be 11 85 d2 74 ?? 8b 45 ?? c1 e0 ?? 03 45 01 8b 4d 08 0f be 11 03 c2 89 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_REntS_SIBT17_2147813443_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/REntS.SIBT17!MTB"
        threat_id = "2147813443"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "REntS"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 14 08 8b 45 ?? 8b 4d ?? 0f b6 34 08 89 f3 83 f3 ?? 88 1c 08}  //weight: 1, accuracy: Low
        $x_1_2 = {88 1c 08 8b 45 ?? 8b 4d ?? 0f b6 34 08 89 f2 83 ea ?? 88 14 08}  //weight: 1, accuracy: Low
        $x_1_3 = {88 14 08 8b 45 ?? 8b 4d ?? 0f b6 34 08 89 f2 81 c2 ?? ?? ?? ?? 88 14 08}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 45 08 80 38 00 0f 84 ?? ?? ?? ?? 8b 45 ?? c1 e0 05 03 45 01 8b 4d 08 0f be 09 01 c8 89 45 01 8b 45 08 83 c0 01 89 45 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_REntS_SIBU_2147814258_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/REntS.SIBU!MTB"
        threat_id = "2147814258"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "REntS"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "AdvertiseManager" wide //weight: 1
        $x_1_2 = "LindaSity.exe" ascii //weight: 1
        $x_1_3 = {03 ca 4f be ?? ?? ?? ?? 8a 11 41 84 d2 74 ?? [0-10] 0f be d2 8d 49 01 33 d6 69 f2 ?? ?? ?? ?? 8a 51 ff 84 d2 75 ?? 81 fe ?? ?? ?? ?? 8b 75 ?? 8b 55 ?? ff 75 ?? 8b 46 24 8d 04 78 0f b7 0c 10 8b 46 1c 8d 04 88 8b 04 10 03 c2 ff d0}  //weight: 1, accuracy: Low
        $x_1_4 = {0f 43 fe 83 f0 ?? 89 85 ?? ?? ?? ?? 83 f1 00 89 8d ?? ?? ?? ?? c7 45 ?? ?? ?? ?? ?? c7 45 ?? ?? ?? ?? ?? c7 85 ?? ?? ?? ?? ?? ?? ?? ?? c7 85 ?? ?? ?? ?? ?? ?? ?? ?? c7 85 ?? ?? ?? ?? ?? ?? ?? ?? c7 85 ?? ?? ?? ?? ?? ?? ?? ?? 8b 95 07 8b b5 09 8b 45 03 03 d0 8b 4d 05 13 f1 83 c2 01 89 95 ?? ?? ?? ?? 83 d6 ?? 89 b5 ?? ?? ?? ?? 8b 85 0b 8b 8d 0d 8b 95 01 8b b5 02 2b d0 89 95 ?? ?? ?? ?? 1b f1 89 b5 ?? ?? ?? ?? 8b b5 1a 8b 95 1b 8b 8d 13 8b 85 15 50 51 52 56 e8 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 89 95 ?? ?? ?? ?? 8b 8d 21 8b 85 22 30 0c 1f 43 3b 5d ?? 73 ?? 8b 55 ?? 8b 75 ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_REntS_SIBU1_2147814260_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/REntS.SIBU1!MTB"
        threat_id = "2147814260"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "REntS"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 ca 4f be ?? ?? ?? ?? 8a 11 41 84 d2 74 ?? [0-10] 0f be d2 8d 49 01 33 d6 69 f2 ?? ?? ?? ?? 8a 51 ff 84 d2 75 ?? 81 fe ?? ?? ?? ?? 8b 75 ?? 8b 55 ?? ff 75 ?? 8b 46 24 8d 04 78 0f b7 0c 10 8b 46 1c 8d 04 88 8b 04 10 03 c2 ff d0}  //weight: 1, accuracy: Low
        $x_1_2 = {2b d0 89 95 ?? ?? ?? ?? 1b f1 89 b5 ?? ?? ?? ?? 8b b5 00 8b 95 01 8b 8d ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 50 51 52 56 e8 ?? ?? ?? ?? 89 45 ?? 89 55 ?? 8b 4d 07 8b 45 08 30 0c 1f 43 3b 5d ?? 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_REntS_SIBV_2147814583_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/REntS.SIBV!MTB"
        threat_id = "2147814583"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "REntS"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ooacmjig.pdb" ascii //weight: 1
        $x_1_2 = {6a 40 68 00 ?? 00 00 8b d8 53 6a 00 ff 15 ?? ?? ?? ?? 6a 00 8b f8 8d 45 ?? 50 53 57 56 ff 15 ?? ?? ?? ?? 33 c9 85 db 74 ?? 8a 04 39 [0-32] 34 ?? [0-32] 34 ?? [0-32] 88 04 39 41 3b cb 72 ?? 6a 00 6a 00 57 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_REntS_SIBV1_2147814585_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/REntS.SIBV1!MTB"
        threat_id = "2147814585"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "REntS"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "gnwpfzse.pdb" ascii //weight: 1
        $x_1_2 = {6a 40 68 00 ?? 00 00 8b d8 53 6a 00 ff 15 ?? ?? ?? ?? 6a 00 8b f8 8d 45 ?? 50 53 57 56 ff 15 ?? ?? ?? ?? 33 c9 85 db 74 ?? 8a 04 39 [0-32] 34 ?? [0-32] 34 ?? [0-32] 88 04 39 41 3b cb 72 ?? 6a 00 6a 00 57 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_REntS_SIBV2_2147814797_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/REntS.SIBV2!MTB"
        threat_id = "2147814797"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "REntS"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 68 00 ?? 00 00 8b d8 53 6a 00 ff 15 ?? ?? ?? ?? 6a 00 8b f8 8d 45 ?? 50 53 57 56 ff 15 ?? ?? ?? ?? 33 c9 85 db 74 ?? 8a 04 39 [0-32] 34 ?? [0-32] fe c8 [0-32] 34 53 [0-32] 88 04 39 41 3b cb 72 ?? 6a 00 6a 00 57 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_REntS_SIBV3_2147814798_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/REntS.SIBV3!MTB"
        threat_id = "2147814798"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "REntS"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 68 00 ?? 00 00 8b d8 53 6a 00 ff 15 ?? ?? ?? ?? 6a 00 8b f8 8d 45 ?? 50 53 57 56 ff 15 ?? ?? ?? ?? 33 c9 85 db 74 ?? [0-10] 8a 04 39 [0-32] 34 ?? [0-32] 34 ?? [0-32] 34 ?? [0-32] 34 ?? [0-32] 88 04 39 41 3b cb 72 ?? 6a 00 6a 00 57 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

