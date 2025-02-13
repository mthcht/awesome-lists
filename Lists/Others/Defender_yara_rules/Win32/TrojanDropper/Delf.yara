rule TrojanDropper_Win32_Delf_ZA_2147576989_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Delf.ZA"
        threat_id = "2147576989"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1500"
        strings_accuracy = "Low"
    strings:
        $x_1000_1 = {b8 0a 00 00 00 e8 ?? ?? ?? ?? 84 c0 74 ?? 6a 01 a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 00 e8 ?? ?? ?? ?? eb 68 b2 04}  //weight: 1000, accuracy: Low
        $x_100_2 = "C:\\mshywin.dll" ascii //weight: 100
        $x_100_3 = "delhuysta.bat" ascii //weight: 100
        $x_100_4 = "ghnavd.exe" ascii //weight: 100
        $x_100_5 = "Liu_mazi" ascii //weight: 100
        $x_100_6 = "del %0" ascii //weight: 100
        $x_100_7 = ":try1" ascii //weight: 100
        $x_100_8 = " goto try1" ascii //weight: 100
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_1000_*) and 5 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Delf_RAG_2147600580_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Delf.RAG"
        threat_id = "2147600580"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\system" ascii //weight: 1
        $x_1_2 = "SYSTEM\\CurrentControlSet\\Services\\BITS\\Parameters" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Setup" ascii //weight: 1
        $x_1_4 = "SYSTEM\\ControlSet003\\Services\\BITS\\Parameters" ascii //weight: 1
        $x_1_5 = "DisableRegistryTools" ascii //weight: 1
        $x_1_6 = "Start DLL Service:" ascii //weight: 1
        $x_1_7 = "cmd.exe /c del" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Delf_RAG_2147600583_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Delf.RAG!dll"
        threat_id = "2147600583"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 53 bb ?? ?? ?? ?? b8 b8 0b 00 00 e8 ?? ?? ?? ?? b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 84 c0 75 07 6a 00 e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? a3 ?? ?? ?? ?? 83 3d ?? ?? ?? ?? 00 75 09 6a 00 e8 ?? ?? ?? ?? eb 1d b8 ?? ?? ?? ?? ba 02 00 00 00 e8 ?? ?? ?? ?? 84 c0 74 0a 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? b9 01 00 00 00 33 d2 b8 02 00 00 00 e8 ?? ?? ?? ?? 33 c9 33 d2 b8 04 00 00 00 e8 ?? ?? ?? ?? eb 05 e8 ?? ?? ?? ?? 83 3b 03 74 05 83 3b 01 75 f1 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 5b 5d c2 08 00}  //weight: 1, accuracy: Low
        $x_1_2 = "BITS" ascii //weight: 1
        $x_1_3 = "svchst.exe" ascii //weight: 1
        $x_1_4 = "avicap32.dll" ascii //weight: 1
        $x_1_5 = "Thread32Next" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Delf_DJ_2147603605_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Delf.DJ"
        threat_id = "2147603605"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4b 75 d8 8d 45 e4 b9 ?? ?? 41 00 8b 15 ?? ?? 41 00 e8 ?? ?? ff ff 8b 55 e4 a1 ?? ?? 41 00 e8 ?? ?? ff ff a1 ?? ?? 41 00 e8 ?? ?? ff ff 8b c6 e8 ?? ?? ff ff 6a 01 68 ?? ?? 41 00 68 ?? ?? 41 00 8d 45 e0 b9 ?? ?? 41 00 8b 15 ?? ?? 41 00 e8 ?? ?? ff ff 8b 45 e0 e8 ?? ?? ff ff 50 68 ?? ?? 41 00 a1 ?? ?? 41 00 50 e8 ?? ?? ff ff 6a 00 68 ?? ?? 41 00 68 ?? ?? 41 00 8d 45 dc b9 ?? ?? 41 00 8b 15 ?? ?? 41 00 e8 ?? ?? ff ff 8b 45 dc e8 ?? ?? ff ff 50 68 ?? ?? 41 00 a1 ?? ?? 41 00 50 e8 ?? ?? ff ff 33 c0 5a 59 59 64 89 10 68}  //weight: 1, accuracy: Low
        $x_1_2 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_3 = "C:\\Program Files\\Common Files\\Microsoft Shared\\Web Folders" ascii //weight: 1
        $x_1_4 = "\\svchost.exe" ascii //weight: 1
        $x_1_5 = "\\vbrun32.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Delf_SS_2147610990_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Delf.SS"
        threat_id = "2147610990"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ba fc ff ff ff 66 b9 02 00 a1 ?? ?? ?? ?? 8b 18 ff 53 08 ba ?? ?? ?? ?? b9 04 00 00 00 a1 ?? ?? ?? ?? e8 ?? ?? ff ff 8d 95 ?? ?? ff ff b8 ?? ?? ?? ?? e8 ?? ?? ff ff 83 3d ?? ?? ?? ?? 00 75 8d 95 ?? ?? ff ff b8 ?? ?? ?? ?? e8 ?? ?? ff ff 33 c9 8b 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 18 ff 53 08 8d 95 ?? ?? ff ff b8 ?? ?? ?? ?? e8 ?? ?? ff ff e9 a1 ?? ?? ?? ?? e8 ?? ?? ff ff 8b d8 a1 ?? ?? ?? ?? e8 ?? ?? ff ff 83 e8 04 3b d8 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {66 b9 02 00 ba fc ff ff ff a1 ?? ?? ?? ?? 8b 18 ff 53 08 ba ?? ?? ?? ?? b9 04 00 00 00 a1 ?? ?? ?? ?? e8 ?? ?? ff ff 8d 95 ?? ?? ff ff b8 ?? ?? ?? ?? e8 ?? ?? ff ff 83 3d ?? ?? ?? ?? 00 75 8d 95 ?? ?? ff ff b8 ?? ?? ?? ?? e8 ?? ?? ff ff 33 c9 8b 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 18 ff 53 08 8d 95 ?? ?? ff ff b8 ?? ?? ?? ?? e8 ?? ?? ff ff e9 a1 ?? ?? ?? ?? e8 ?? ?? ff ff 8b d8 a1 ?? ?? ?? ?? e8 ?? ?? ff ff 83 e8 04 3b d8 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDropper_Win32_Delf_TD_2147611799_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Delf.TD"
        threat_id = "2147611799"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0e 50 72 6f 63 75 72 61 44 72 69 76 65 72 73 ?? ?? ?? ?? ?? ?? 04 44 69 63 6f ?? ?? ?? ?? ?? ?? 0a 43 72 69 41 72 71 75 69 76 6f ?? ?? ?? ?? ?? ?? 0c 41 62 72 65 50 72 6f 63 65 73 73 6f ?? ?? ?? ?? ?? ?? 0a 46 6f 72 6d 43 72 65 61 74 65 ?? ?? ?? ?? ?? ?? 05 53 74 61 72 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Delf_TE_2147621503_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Delf.TE"
        threat_id = "2147621503"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {b2 08 b0 04 e8 ?? ?? ff ff 8d 4d ?? b2 03 b0 02 e8 ?? ?? ff ff 8d 4d ?? b2 02 b0 01 e8}  //weight: 10, accuracy: Low
        $x_10_2 = {6a 0a 6a 00 e8}  //weight: 10, accuracy: High
        $x_10_3 = {45 6e 75 6d 52 65 73 6f 75 72 63 65 4e 61 6d 65 73 41 00}  //weight: 10, accuracy: High
        $x_1_4 = {80 7d ff 00 74 4f 0f b6 75 ff 85 f6 7e 47 b8 13 00 00 00 e8 ?? ?? ?? ff 8a 90 ?? ?? ?? 00 8d 45 f4}  //weight: 1, accuracy: Low
        $x_1_5 = {74 51 0f b6 75 fb 85 f6 7e 49 b8 13 00 00 00 e8 ?? ?? ?? ff 0f b6 90 ?? ?? ?? 00 8d 45 f4 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Delf_TF_2147622810_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Delf.TF"
        threat_id = "2147622810"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {76 40 00 d6 07 66 c7 05 ?? 76 40 00 05 00 66 c7 05 ?? 76 40 00 19 00 66 c7 05 ?? 76 40 00 11 00 66 c7 05 ?? 76 40 00 00 00 66 c7 05 ?? 76 40 00 00 00 68 ?? 76 40 00 68 ?? 76 40 00 68 ?? 76 40 00 68 ?? 76 40 00 ff 35 6c 76 40 00 ff 35 70 76 40 00}  //weight: 10, accuracy: Low
        $x_1_2 = {6c 6f 67 6f 78 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_3 = {6e 74 6c 61 70 69 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_4 = {6b 6e 72 2e 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Delf_CZ_2147623051_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Delf.CZ"
        threat_id = "2147623051"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff ff ff ff 04 00 00 00 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_2 = {84 c0 74 45 6a 01 a1 ?? ?? ?? ?? e8 ?? ?? ff ff 50 e8 ?? ?? ff ff a1 ?? ?? ?? ?? e8 ?? ?? ff ff 33 db eb 17 43 83 fb 64 7d 1f 6a 64 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {33 db 8b c3 99 f7 3d ?? ?? ?? ?? a1 ?? ?? ?? ?? 0f b6 04 10 8b 15 ?? ?? ?? ?? 0f b6 14 1a 2b d0 81 c2 00 01 00 00 81 e2 ff 00 00 80 79 08 4a 81 ca 00 ff ff ff 42 a1 ?? ?? ?? ?? 88 14 18 43 ?? 75 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Delf_DM_2147623052_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Delf.DM"
        threat_id = "2147623052"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks" ascii //weight: 1
        $x_1_2 = {07 77 69 6e 64 6f 77 73}  //weight: 1, accuracy: High
        $x_1_3 = {8b f8 85 ff 0f 84 a2 00 00 00 57 a1 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 8b d8 85 db 0f 84 8c 00 00 00 53 e8 ?? ?? ?? ?? 8b e8 85 ed 75 08 53 e8 ?? ?? ?? ?? eb 78 6a 00 68 80 00 00 00 6a 02 6a 00 6a 00 68 00 00 00 40 56 e8 ?? ?? ?? ?? 8b f0 83 fe ff 75 0f 8b c3 e8 ?? ?? ?? ?? 53 e8 ?? ?? ?? ?? eb 4a 57 a1 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 8b f8 6a 00 8d 44 24 04 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Delf_DP_2147624762_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Delf.DP"
        threat_id = "2147624762"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 85 fb fe ff ff 50 68 05 01 00 00 e8 ?? ?? ff ff 8d 85 f4 fe ff ff 8d 95 fb fe ff ff b9 05 01 00 00 e8 ?? ?? ff ff 8b 85 f4 fe ff ff 8b d3 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 01 6a 00 6a 00 8d 45 fc e8 ?? ?? ff ff 8d 45 fc 8b 15 ?? ?? ?? ?? e8 ?? ?? ff ff 8b 45 fc e8 ?? ?? ff ff 50 6a 00 6a 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Delf_DV_2147627228_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Delf.DV"
        threat_id = "2147627228"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 7d fe ff ff a1 ?? ?? ?? ?? 50 e8 ?? ?? ff ff b8 83 01 00 00 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {83 fa 04 7c 0d 8b 18 0f b6 1c 13 33 d9 8b 38 88 1c 17 42 4e 75 ea}  //weight: 1, accuracy: High
        $x_1_3 = {75 0b 8b 43 34 03 43 28 89 45 c0 eb 06 03 43 28 89 45 c0 8d 85 10 ff ff ff}  //weight: 1, accuracy: High
        $x_1_4 = {2d 66 75 63 6b 20 22 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDropper_Win32_Delf_EI_2147647005_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Delf.EI"
        threat_id = "2147647005"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "Bind File succeed." ascii //weight: 4
        $x_4_2 = "Fnally File Path Can Not Empty!" ascii //weight: 4
        $x_3_3 = "Pro_Bind" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Delf_EM_2147652189_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Delf.EM"
        threat_id = "2147652189"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\" /NORESTART /SILENT" ascii //weight: 2
        $x_3_2 = "sidrunet.tid" ascii //weight: 3
        $x_3_3 = "\\ssinitar.exe" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Delf_BL_2147734588_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Delf.BL!MTB"
        threat_id = "2147734588"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {c7 45 f8 01 00 00 00 8b 45 fc 8b 55 f8 8a 5c 10 ff 80 f3 0a 8d 45 f4 8b d3 e8}  //weight: 3, accuracy: High
        $x_2_2 = "mpcz&*nolfk~o" ascii //weight: 2
        $x_1_3 = "%cdnor%mo~ilm5cn7" ascii //weight: 1
        $x_1_4 = "/index/getcfg?id=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

