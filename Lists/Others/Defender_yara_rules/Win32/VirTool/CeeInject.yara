rule VirTool_Win32_Ceeinject_NE_2147718325_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Ceeinject.NE!bit"
        threat_id = "2147718325"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Ceeinject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b cb 33 f6 66 d1 e8 66 d1 e0 8b 35 c0 61 42 00 97 8b fe ff d7 33 c0}  //weight: 2, accuracy: High
        $x_2_2 = {eb d4 8b 85 ?? ?? ?? ?? 0f af 85 ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 2b 8d ?? ?? ?? ?? 03 c1 0f be 55 f3 03 d0 88 55 f3}  //weight: 2, accuracy: Low
        $x_1_3 = "malwaregen from avast" ascii //weight: 1
        $x_1_4 = "markets sssasss:" ascii //weight: 1
        $x_1_5 = "kolll sd s vvffd:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Ceeinject_NH_2147718382_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Ceeinject.NH!bit"
        threat_id = "2147718382"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Ceeinject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%ib8gnjjkllllo.dll" ascii //weight: 1
        $x_1_2 = {8b d8 83 e3 01 f7 db 81 e3 20 83 b8 ed d1 e8 33 c3 4f 79 ec}  //weight: 1, accuracy: High
        $x_1_3 = {0f b6 39 4a 6a 07 33 c7 5f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Ceeinject_NI_2147718575_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Ceeinject.NI!bit"
        threat_id = "2147718575"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Ceeinject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 25 8b 55 ?? 8b 45 ?? 0f b7 0c 50 8b 55 ?? 8b 45 ?? 03 04 8a eb}  //weight: 1, accuracy: Low
        $x_1_2 = {50 6a 00 6a 00 8b 4d ?? 51 6a 00 6a 00 8b 15 ?? ?? ?? ?? ff d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Ceeinject_NJ_2147718576_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Ceeinject.NJ!bit"
        threat_id = "2147718576"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Ceeinject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {29 c0 2b 03 f7 d8 f8 83 db ?? f7 d8 f8 83 d8 ?? c1 c8 ?? d1 c0 31 c8 f8 83 d8 01 8d 08 c1 c1 ?? d1 c9 f7 d9 50 8f 07 83 ef ?? f8 83 d6 ?? 68}  //weight: 1, accuracy: Low
        $x_1_2 = {68 04 07 00 00 5e 8d 1d ?? ?? ?? ?? 53 8d 0d ?? ?? ?? ?? 51 8d 05 ?? ?? ?? ?? 50 8d 15 ?? ?? ?? ?? 52 8d 15 ?? ?? ?? ?? 52 8d 0d ?? ?? ?? ?? 83 c1 ?? ff 11}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Ceeinject_NL_2147719010_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Ceeinject.NL!bit"
        threat_id = "2147719010"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Ceeinject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f8 89 85 ?? ?? ?? ?? 8b 4d ec 03 8d ?? ?? ?? ?? 8b 55 f4 03 95 ?? ?? ?? ?? 8a 02 88 01 8b 4d f8 83 c1 01 89 4d f8 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {8b f6 ff 35 ?? ?? ?? ?? 8b f6 ff 35 ?? ?? ?? ?? 8b f6 33 d2 8d 05 ?? ?? ?? ?? 48 03 10 8b d2 8b d2 52 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Ceeinject_NS_2147719014_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Ceeinject.NS!bit"
        threat_id = "2147719014"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Ceeinject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a d0 8b 85 ?? ?? ?? ?? 03 85 ?? ?? ?? ?? 8a 95 ?? ?? ?? ?? 8a 08 e8 ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 03 8d ?? ?? ?? ?? 88 01 33 d2 74}  //weight: 1, accuracy: Low
        $x_1_2 = "3315315$" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Ceeinject_NQ_2147719132_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Ceeinject.NQ!bit"
        threat_id = "2147719132"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Ceeinject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 6a 00 52 ff d6 8b 8d ?? ?? ?? ?? 8b 95 ?? ?? ?? ?? 89 85}  //weight: 1, accuracy: Low
        $x_1_2 = {7e 7c 8d 9b ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 2b 8d ?? ?? ?? ?? 3b f9 72 05 e8 ?? ?? ?? ?? 8b 95 ?? ?? ?? ?? 8a 04 17}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Ceeinject_NX_2147719411_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Ceeinject.NX!bit"
        threat_id = "2147719411"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Ceeinject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f 64 64 65 00 00 00 64 64 65 65 78 65 63 00 5b 6f 70 65 6e 28 22 25 31 22 29 5d}  //weight: 1, accuracy: High
        $x_1_2 = "%s\\shell\\printto\\%s" ascii //weight: 1
        $x_1_3 = {8b 01 33 d2 6a ?? 5b f7 f3 80 c2 ?? 88 14 37 8b 01 33 d2 f7 f3 47 85 c0 89 01 77}  //weight: 1, accuracy: Low
        $x_1_4 = {8a 1c 30 8b 55 ?? 30 1c 32 8a 14 32 30 14 30 8a 14 30 8b 5d ?? 30 14 33 48 ff 45 ?? 8b d0 2b 55}  //weight: 1, accuracy: Low
        $x_1_5 = {41 41 eb 0d b2 ?? f6 ea 02 44 0e ?? 2c ?? 83 c1 ?? 88 47 ff c6 07 00 47 3b 4d e4 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Ceeinject_NY_2147719819_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Ceeinject.NY!bit"
        threat_id = "2147719819"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Ceeinject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 06 83 c6 ?? 2b 05 ?? ?? ?? ?? c1 c0 ?? 33 05 ?? ?? ?? ?? c1 0d 01 ?? ?? ?? ?? ab bb ?? ?? ?? ?? 3b f3 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c0 52 50 68 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Ceeinject_MC_2147719820_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Ceeinject.MC!bit"
        threat_id = "2147719820"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Ceeinject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {85 c9 7c 0f 8b c1 99 6a ?? 5b f7 fb 8a 44 15 ?? 30 04 39 41 3b ce 72 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {03 ce 8b c1 ff 70 ?? 8b 48 ?? 8b 40 ?? 03 05 ?? ?? ?? ?? 03 ce 51 50 ff d3 0f b7 47 ?? 45 3b e8 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Ceeinject_QE_2147720952_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Ceeinject.QE!bit"
        threat_id = "2147720952"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Ceeinject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {dc ca 50 d8 c3 d3 d8 58 d8 c2 d8 c4 d9 f7 df 5d fe ?? ed}  //weight: 1, accuracy: Low
        $x_1_2 = {60 64 8b 1d 18 00 00 00 89 1d ?? ?? ?? ?? 61 [0-6] 8b ?? 30 [0-18] 8b ?? 0c [0-18] 8b ?? 1c [0-18] 8b ?? 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Ceeinject_TC_2147724934_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Ceeinject.TC!bit"
        threat_id = "2147724934"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Ceeinject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 f7 ff 80 c2 30 33 c0 8a c1 88 14 06 8b c3 bb ?? ?? ?? ?? 99 f7 fb 8b d8 49 85 db 07 00 8b c3 bf}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 04 68 00 10 00 00 8b 45 00 2b 06 50 8b 06 50 e8 ?? ?? ?? ?? 85 c0 75 06 33 c0 89 03}  //weight: 1, accuracy: Low
        $x_1_3 = {8b d7 8b 0d ?? ?? ?? ?? 32 54 19 ff f6 d2 88 54 18 ff 43 4e 75 e3 07 00 8b c5 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Ceeinject_TJ_2147724940_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Ceeinject.TJ!bit"
        threat_id = "2147724940"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Ceeinject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 03 8a 00 34 7b 8b 15 ?? ?? ?? ?? 03 13 88 02 90 ff 03 81 3b 5d 57 00 00 75 e0 05 00 a1}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 03 40 bf 8a 00 00 00 33 d2 f7 f7 8b c1 03 03 88 10 90 ff 03 81 3b 57 b9 46 22}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Ceeinject_TJ_2147724940_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Ceeinject.TJ!bit"
        threat_id = "2147724940"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Ceeinject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 56 8b 7c 24 0c 8b 4c 24 10 8b 74 24 14 8b 54 24 18 85 d2 74 0e ac 52 30 07 5a 4a 47 e2 f3 5e 5b 33 c0 c3}  //weight: 1, accuracy: High
        $x_1_2 = {48 89 5c 24 08 57 48 83 ec 20 48 8b 41 10 48 8b f9 48 8b 00 48 3b 47 10 74 33 80 78 18 00 74 f1 48 8b 18 48 3b 47 10 74 1f 48 8b 48 08 48 89 19 48 8b 48 08 48 8b 10 48 89 4a 08 48 8b c8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Ceeinject_TK_2147725018_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Ceeinject.TK!bit"
        threat_id = "2147725018"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Ceeinject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 d2 8d 43 01 b9 1d 00 00 00 33 d2 f7 f1 81 fa ff 00 00 00 76 05 e8 ?? ?? ?? ?? 8b c7 03 c3 88 10}  //weight: 1, accuracy: Low
        $x_1_2 = {03 c3 8a 00 [0-16] 89 db [0-16] 34 11 8b 15 ?? ?? ?? ?? 03 d3 88 02 [0-16] 89 db 89 f6 43 81 fb 56 5b 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Ceeinject_TM_2147725199_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Ceeinject.TM!bit"
        threat_id = "2147725199"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Ceeinject"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 43 01 b9 85 00 00 00 33 d2 f7 f1 81 fa ff 00 00 00 76 ?? e8 ?? ?? ?? ?? 8b c6 03 c3 88 10}  //weight: 1, accuracy: Low
        $x_1_2 = {03 c3 8a 00 [0-16] 34 46 8b 15 ?? ?? ?? ?? 03 d3 88 02 [0-16] 43 81 fb f9 5c 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

