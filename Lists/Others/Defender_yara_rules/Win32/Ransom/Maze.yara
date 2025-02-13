rule Ransom_Win32_Maze_DH_2147744075_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Maze.DH!MTB"
        threat_id = "2147744075"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Maze"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\shit\\gavno.pdb" ascii //weight: 1
        $x_1_2 = "C:\\aaa_TouchMeNot_.txt" ascii //weight: 1
        $x_1_3 = "dkartinka.bmp" wide //weight: 1
        $x_1_4 = "Vitalikremez detector" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Maze_PA_2147745257_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Maze.PA!MTB"
        threat_id = "2147745257"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Maze"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"%s\" shadowcopy delete" wide //weight: 1
        $x_1_2 = "Maze Ransomware" wide //weight: 1
        $x_1_3 = "Your files have been encrypted by" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Maze_PA_2147745257_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Maze.PA!MTB"
        threat_id = "2147745257"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Maze"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 4d f8 83 c1 01 89 4d f8 8b 55 f8 3b 55 ?? 73 ?? 8b 45 10 03 45 f8 0f b6 08 8b 55 f8 0f b6 44 15 ?? 33 c8 8b 55 ?? 03 55 f8 88 0a eb}  //weight: 10, accuracy: Low
        $x_1_2 = {8b 55 f4 33 55 f0 03 55 ec 8b 45 fc 8b 4d 08 03 14 81 8b 45 fc 8b 4d 08 89 14 81}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Maze_PB_2147745259_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Maze.PB!MTB"
        threat_id = "2147745259"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Maze"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 06 46 85 c0 74 ?? bb 00 00 00 00 23 d3 21 5d ?? 83 45 ?? 08 d1 c0 8a fc 8a e6 d1 cb ff 4d ?? 75 ?? 6a 00 89 0c 24 33 c9 33 cb 8b c1 59 aa 49 75}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 06 46 85 c0 74 ?? bb 00 00 00 00 23 d3 21 5d fc 83 45 fc 08 d1 c0 8a fc 8a e6 d1 cb ff 4d fc 75 ?? 6a 00 89 14 24 2b d2 33 d3 8b c2 5a aa 49 75}  //weight: 1, accuracy: Low
        $x_1_3 = {0f b6 1c 30 6a 00 89 3c 24 2b ff 33 7d ?? 8b d7 5f d3 c2 23 d3 ac 0a c2 88 07 47 ff 4d ?? 75}  //weight: 1, accuracy: Low
        $x_1_4 = {0f b6 1c 30 6a 00 89 34 24 33 f6 03 75 ?? 8b d6 5e d3 c2 23 d3 ac 0a c2 88 07 47 ff 4d f8 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Ransom_Win32_Maze_PC_2147749191_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Maze.PC!MTB"
        threat_id = "2147749191"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Maze"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {8b 0f 8b f1 8b 57 ?? 8d 7f 04 c1 c6 0f 8b c1 c1 c0 0d 33 f0 c1 e9 0a 33 f1 8b c2 8b ca c1 c8 07 c1 c1 0e 33 c8 c1 ea 03 33 ca 03 f1 03 77 ?? 03 77 ?? 03 f3 43 89 77 04 81 fb ?? ?? 00 00 72}  //weight: 20, accuracy: Low
        $x_1_2 = {c1 c0 09 0f b6 8e ?? ?? 00 00 c1 ca 0a 33 d0 8b 86 ?? ?? 00 00 c1 c8 08 03 d0 0f b6 86 ?? ?? 00 00 03 54 be 04 8b 84 86 ?? ?? 00 00 03 84 8e ?? ?? 00 00 33 d0 89 54 be 04 89 96 ?? ?? 00 00 8b 44 be 0c 8b 96 ?? ?? 00 00 0f b6 8e ?? ?? 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Maze_P_2147749744_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Maze.P!MSR"
        threat_id = "2147749744"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Maze"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\JDUIHiuf\\IDisjopjcnb" wide //weight: 1
        $x_1_2 = "kill\\yourself\\@YongruiTan\\chinese\\idiot.pdb" ascii //weight: 1
        $x_1_3 = "you our job also would be fucking boring as hell" wide //weight: 1
        $x_1_4 = "DjDjdfodgs" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Maze_Q_2147750767_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Maze.Q!MSR"
        threat_id = "2147750767"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Maze"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Killyourself.dll" ascii //weight: 2
        $x_1_2 = "wchCrypt32" ascii //weight: 1
        $x_1_3 = "dwShellCodeSize" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Maze_B_2147750984_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Maze.B!MSR"
        threat_id = "2147750984"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Maze"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\teg.gp\\fssdf.pdb" ascii //weight: 1
        $x_1_2 = "File serves as a driver of North Korea Power" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Maze_GG_2147753782_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Maze.GG!MTB"
        threat_id = "2147753782"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Maze"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wchCrypt32" ascii //weight: 1
        $x_1_2 = "dwShellCodeSize" ascii //weight: 1
        $x_1_3 = "keystream" ascii //weight: 1
        $x_1_4 = "fnName" ascii //weight: 1
        $x_1_5 = "PDBOpenValidate5" ascii //weight: 1
        $x_1_6 = "DllInstall" ascii //weight: 1
        $x_1_7 = "DllRegisterServer" ascii //weight: 1
        $x_1_8 = ".pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Maze_PI_2147754923_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Maze.PI!MTB"
        threat_id = "2147754923"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Maze"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d b8 83 c1 01 89 4d b8 8b 55 b8 3b 55 18 73 [0-4] 8b 45 ?? 03 45 b8 0f b6 08 8b 55 b8 0f b6 44 15 bc 33 c8 8b 55 14 03 55 b8 88 0a eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Maze_PI_2147754923_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Maze.PI!MTB"
        threat_id = "2147754923"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Maze"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8b 4d b8 83 c1 01 89 4d b8 8b 55 b8 3b 55 18 73 [0-4] 8b 45 ?? 03 45 b8 0f b6 08 8b 55 b8 0f b6 44 15 bc 33 c8 8b 55 14 03 55 b8 88 0a eb}  //weight: 3, accuracy: Low
        $x_3_2 = "youaremyshame!!" ascii //weight: 3
        $x_1_3 = "\\ransomware\\hutchins.pdb" ascii //weight: 1
        $x_1_4 = "\\fucking\\idiotic\\nonexisting\\file\\with\\pdb\\extension.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Maze_PK_2147755042_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Maze.PK!MTB"
        threat_id = "2147755042"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Maze"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b f0 2b f8 8d 4c 24 ?? 03 ca 8a 04 0e 32 01 42 88 04 0f 3b d3 72}  //weight: 1, accuracy: Low
        $x_1_2 = {33 44 24 14 89 07 8b 46 04 33 44 24 18 89 47 04 8b 46 08 33 44 24 1c 89 47 08 8b 46 0c 33 44 24 20 89 47 0c 8b 46 10 33 44 24 24 89 47 10 8b 46 14 33 44 24 28 89 47 14 8b 46 18 33 44 24 2c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Maze_PS_2147756584_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Maze.PS!MTB"
        threat_id = "2147756584"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Maze"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b c3 2b fb 8d 5d ?? 2b 5d ?? eb 07 8d a4 24 ?? ?? ?? ?? 8a 0c 03 8d 40 ?? 32 4c 07 ?? 88 48 ?? 4a 75}  //weight: 2, accuracy: Low
        $x_1_2 = "CardersLiveMatter.pdb" ascii //weight: 1
        $x_1_3 = "gfg9urwyf7.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Maze_DSA_2147762022_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Maze.DSA!MTB"
        threat_id = "2147762022"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Maze"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "shit.pdb" ascii //weight: 1
        $x_1_2 = "blablabla" ascii //weight: 1
        $x_1_3 = "To be happy one must at least once a life ra" ascii //weight: 1
        $x_1_4 = "creepyshit.log" ascii //weight: 1
        $x_1_5 = "open this file on your host to see the next part" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_Win32_Maze_PD_2147763627_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Maze.PD!MTB"
        threat_id = "2147763627"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Maze"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\wbem\\wmic.exe" wide //weight: 1
        $x_1_2 = "\"%s\" shadowcopy delete" wide //weight: 1
        $x_1_3 = "DECRYPT-FILES.html" wide //weight: 1
        $x_1_4 = "Dear %s Your files have been encrypted!" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Maze_ARA_2147897438_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Maze.ARA!MTB"
        threat_id = "2147897438"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Maze"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {e9 0c 01 00 00 c6 45 e4 43 c6 45 e5 72 c6 45 e6 79 c6 45 e7 70 c6 45 e8 74 c6 45 e9 53 c6 45 ea 74 c6 45 eb 72 c6 45 ec 69 c6 45 ed 6e c6 45 ee 67 c6 45 ef 54 c6 45 f0 6f c6 45 f1 42 c6 45 f2 69 c6 45 f3 6e c6 45 f4 61 c6 45 f5 72 c6 45 f6 79 c6 45 f7 41 c6 45 f8 00 8d 4d e4 51 8b 55 b8 52}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

