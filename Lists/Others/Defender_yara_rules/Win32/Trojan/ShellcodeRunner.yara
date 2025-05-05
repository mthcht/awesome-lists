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

