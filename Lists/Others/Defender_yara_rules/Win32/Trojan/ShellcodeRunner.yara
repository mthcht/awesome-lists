rule Trojan_Win32_ShellcodeRunner_CCIA_2147906086_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShellcodeRunner.CCIA!MTB"
        threat_id = "2147906086"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 c0 01 d0 29 c1 89 ca 0f b6 44 15 ?? 31 f0 89 c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ShellcodeRunner_EK_2147906189_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShellcodeRunner.EK!MTB"
        threat_id = "2147906189"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 84 35 d0 fd ff ff 88 8c 35 d0 fd ff ff 0f b6 c8 88 84 3d d0 fd ff ff 0f b6 84 35 d0 fd ff ff 03 c8 0f b6 c1 8b 8d d8 fe ff ff 0f b6 84 05 d0 fd ff ff 32 44 13 08 88 04 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ShellcodeRunner_RP_2147907151_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShellcodeRunner.RP!MTB"
        threat_id = "2147907151"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hanshouwork_default_aspx" ascii //weight: 1
        $x_1_2 = "hanshouwork_listsview_aspx" ascii //weight: 1
        $x_1_3 = "App_global.asax.nvqtah6k" ascii //weight: 1
        $x_1_4 = "Create_ASP_hanshouwork_default_aspx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ShellcodeRunner_CO_2147907991_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShellcodeRunner.CO!MTB"
        threat_id = "2147907991"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {46 8a 84 35 ?? ?? ff ff 88 8c 35 ?? ?? ff ff 0f b6 c8 88 84 3d ?? ?? ff ff 0f b6 84 35 ?? ?? ff ff 03 c8 0f b6 c1 8b 8d ?? ?? ff ff 0f b6 84 05 ?? ?? ff ff 32 44 1a 08 88 04 11 42 81 fa}  //weight: 4, accuracy: Low
        $x_1_2 = {83 c4 0c 8d 44 24 30 50 8d 84 24 5c 01 00 00 50 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ShellcodeRunner_YAV_2147911991_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShellcodeRunner.YAV!MTB"
        threat_id = "2147911991"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4c 24 58 8d 14 07 03 54 24 28 0f b6 0c 01 83 c0 01 30 0a 39 c6 75 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ShellcodeRunner_AI_2147913707_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShellcodeRunner.AI!MTB"
        threat_id = "2147913707"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {f3 a5 66 a5 8b f4 6a 40 68 00 30 00 00 68 ?? ?? 00 00 6a 00 ff 15 ?? ?? ?? 00 3b f4 e8}  //weight: 2, accuracy: Low
        $x_2_2 = "Shellcode is written to allocated memory!" ascii //weight: 2
        $x_1_3 = "msfhe byhlcodhShel1" ascii //weight: 1
        $x_1_4 = "hll Ah32.dhuser0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ShellcodeRunner_HNC_2147922231_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShellcodeRunner.HNC!MTB"
        threat_id = "2147922231"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 c2 42 30 01 3b d6}  //weight: 2, accuracy: High
        $x_1_2 = {2a d0 80 c2 ?? 30 54 0d ?? 41 83 f9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ShellcodeRunner_MEZ_2147935215_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShellcodeRunner.MEZ!MTB"
        threat_id = "2147935215"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {f7 d7 8b 45 fc 33 d2 bb 10 00 00 00 f7 f3 0f b6 92 ?? ?? ?? ?? 23 fa 0b f7 0b ce 8b 45 f8 03 45 fc 88 08 e9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ShellcodeRunner_CCIR_2147936514_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShellcodeRunner.CCIR!MTB"
        threat_id = "2147936514"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {c6 45 e8 3f c6 45 e9 6f c6 45 ea 2b c6 45 eb d3 c6 45 ec 20 c6 45 ed b2 c6 45 ee c1 c6 45 ef 77 c6 45 f0 42 c6 45 f1 4c c6 45 f2 63 c6 45 f3 6d c6 45 f4 09 c6 45 f5 8a c6 45 f6 ec c6 45 f7 ed c6 45 f8 a3 c6 45 f9 29 c6 45 fa 36}  //weight: 2, accuracy: High
        $x_1_2 = {51 50 53 57 53 ff 75 0c ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ShellcodeRunner_DAA_2147936778_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShellcodeRunner.DAA!MTB"
        threat_id = "2147936778"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {55 8d ac 24 58 fd ff ff 81 ec 28 03 00 00 a1 ?? ?? ?? ?? 89 85 a4 02 00 00 a1 64 99 42 00 85 c0 74}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ShellcodeRunner_DB_2147938206_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShellcodeRunner.DB!MTB"
        threat_id = "2147938206"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {89 c1 8b 55 f0 8b 45 08 01 d0 31 cb 89 da 88 10 83 45 f0 01 83 55 f4 00 8b 45 f0 8b 55 f4 3b 45 e0 89 d0 1b 45 e4}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ShellcodeRunner_BAA_2147940677_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShellcodeRunner.BAA!MTB"
        threat_id = "2147940677"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 10 0f b6 14 10 23 f2 f7 d6 23 ce 8b 85 ?? ?? ?? ?? 03 45 98 88 08 eb}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ShellcodeRunner_SCP_2147943379_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShellcodeRunner.SCP!MTB"
        threat_id = "2147943379"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {c1 e8 04 69 c0 ?? ?? ?? ?? 29 c1 89 c8 83 c0 64 89 04 24}  //weight: 3, accuracy: Low
        $x_2_2 = {89 d0 69 c0 ?? ?? ?? ?? 29 c1 89 c8 05 ?? ?? ?? ?? 89 04 24 e8}  //weight: 2, accuracy: Low
        $x_1_3 = "%s\\sys_check_%lu.tmp" ascii //weight: 1
        $x_1_4 = "resource_data.png" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ShellcodeRunner_NIT_2147943747_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShellcodeRunner.NIT!MTB"
        threat_id = "2147943747"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {22 6c 69 62 2e 6d 69 6e 2e 6a 73 22 3b 0d 0a 20 20 20 20 20 20 20 20 75 73 69 6e 67 20 28 46 69 6c 65 53 74 72 65 61 6d 20 66 73 20 3d 20 6e 65 77 20 46 69 6c 65 53 74 72 65 61 6d 28 70 61 74 68 2c 20 46 69 6c 65 4d 6f 64 65 2e 4f 70 65 6e 2c 20 46 69 6c 65 41 63 63 65 73 73 2e 52 65 61 64 29 29}  //weight: 2, accuracy: High
        $x_2_2 = {6c 65 6e 20 3d 20 28 75 69 6e 74 29 66 73 2e 4c 65 6e 67 74 68 20 2f 20 34 20 2d 20 32 35 36 3b 0d 0a 0d 0a 20 20 20 20 20 20 20 20 20 20 20 20 49 6e 74 50 74 72 20 61 20 3d 20 42 6c 61 47 65 74 28 6c 65 6e 29 3b 0d 0a 0d 0a 20 20 20 20 20 20 20 20 20 20 20 20 66 6f 72 20 28 69 6e 74 20 69 20 3d 20 30 3b 20 69 20 3c 20 32 35 36 3b 20 69 2b 2b 29 20 7b 0d 0a 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 69 66 20 28 66 73 2e 52 65 61 64 28 62 75 66 66 65 72 2c 20 30 2c 20 34 29 20 21 3d 20 34 29}  //weight: 2, accuracy: High
        $x_1_3 = ".WriteByte(a, pos, (byte)((map[key] + 256 - (pos % 256)) % 256))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ShellcodeRunner_AGZ_2147944052_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShellcodeRunner.AGZ!MTB"
        threat_id = "2147944052"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {f7 e9 03 d1 c1 fa 05 8b c2 c1 e8 1f 03 c2 8a d0 c0 e2 03 2a d0 8a c1 c0 e2 03 2a c2 04 39 30 44 0d ?? 41 83 f9 1d 7c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ShellcodeRunner_ISA_2147947863_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShellcodeRunner.ISA!MTB"
        threat_id = "2147947863"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 9c bf b9 b1 35 79 66 81 e7 b9 46 c1 e7 a7 66 f7 df 8b 7c 24 04 c7 44 24 04 06 c8 ef 7f ff 74 24 00 9d 8d 64 24 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ShellcodeRunner_MMA_2147948386_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShellcodeRunner.MMA!MTB"
        threat_id = "2147948386"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 c0 5b 0f b6 34 10 33 f1 8a 8e ?? ?? ?? ?? 30 4c 07 40 0f b6 4c 07 40 40 83 f8 10 7c}  //weight: 5, accuracy: Low
        $x_4_2 = {8b 55 14 8b c8 83 e1 ?? 8a 0c 11 30 0c 18 40 3b 45 1c 7c}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ShellcodeRunner_NS_2147948818_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShellcodeRunner.NS!MTB"
        threat_id = "2147948818"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {33 d2 8a d4 89 15 40 ad 40 00 8b c8 81 e1 ff 00 00 00 89 0d 3c ad 40 00 c1 e1 08 03 ca 89 0d 38 ad 40 00 c1 e8 10 a3 34 ad 40 00 6a 01 e8 98 16 00 00 59 85 c0 75 08}  //weight: 3, accuracy: High
        $x_1_2 = {a3 18 ad 40 00 e8 d8 0e 00 00 e8 1a 0e 00 00 e8 25 0b 00 00 89 75 d0 8d 45 a4 50}  //weight: 1, accuracy: High
        $x_1_3 = "Videos\\login.bin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ShellcodeRunner_PAHP_2147951165_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShellcodeRunner.PAHP!MTB"
        threat_id = "2147951165"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {6a 18 59 33 ff 33 c0 ac 3c 61 7c 02 2c 20 c1 cf 0d 03 f8 e2 f0 81 ff 5b bc 4a 6a 8b 5a 10 8b 12 75}  //weight: 3, accuracy: High
        $x_2_2 = {8b 0a 69 c0 95 e9 d1 5b 69 c9 95 e9 d1 5b 8b d9 c1 eb 18 33 d9 69 db 95 e9 d1 5b 33 c3 83 ee 04 83 c2 04 4f 75}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ShellcodeRunner_PAHQ_2147951166_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShellcodeRunner.PAHQ!MTB"
        threat_id = "2147951166"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShellcodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {c6 04 0f 00 8a 19 2a d8 fe cb 40 88 1c 0a 41 3b 45 fc 76 ec}  //weight: 3, accuracy: High
        $x_2_2 = {8a 06 88 04 31 46 84 c0 75 f6}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

