rule BrowserModifier_Win32_Diplugem_213571_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Diplugem"
        threat_id = "213571"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Diplugem"
        severity = "91"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {47 6f 6f 67 6c 65 55 70 64 61 74 65 48 65 6c 70 65 72 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_2 = {74 02 eb 35 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 74 02 eb 27 c7 45 fc 00 00 00 00 eb 09}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Diplugem_213571_1
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Diplugem"
        threat_id = "213571"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Diplugem"
        severity = "91"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b7 ff 2b d1 89 45 fc 53 3b f7 75 02 33 f6 8a 04 0a 8b 5d 08 32 04 1e 46 88 01 41 ff 4d fc 75 e8 5b}  //weight: 1, accuracy: High
        $x_1_2 = "%s?q=%08X&t=%08X&p=%d&v=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Diplugem_213571_2
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Diplugem"
        threat_id = "213571"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Diplugem"
        severity = "91"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {51 68 de c0 ad de e8}  //weight: 3, accuracy: High
        $x_3_2 = {52 68 ca da 3e 30 e8}  //weight: 3, accuracy: High
        $x_2_3 = {83 c1 02 d1 e9 8d 14 8d 04 00 00 00 89 55 ?? 8b 45 ?? 8b 4d ?? 8d 54 01 02 52 6a 00 ff 15}  //weight: 2, accuracy: Low
        $x_1_4 = "3735929054 809425610" ascii //weight: 1
        $x_1_5 = "/pid=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_Diplugem_213571_3
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Diplugem"
        threat_id = "213571"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Diplugem"
        severity = "91"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "37.1329.%d.%d" wide //weight: 1
        $x_1_2 = "%appdata%\\appdataFr" wide //weight: 1
        $x_1_3 = "$$$HIDE_MAGIC$$$" ascii //weight: 1
        $x_1_4 = {33 d2 81 3d ?? ?? ?? ?? 8d c3 ab b9 0f 45 ca 3b}  //weight: 1, accuracy: Low
        $x_1_5 = {33 d2 81 3d ?? ?? ?? ?? 8f c3 ab b9 0f 45 ca 3b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule BrowserModifier_Win32_Diplugem_213571_4
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Diplugem"
        threat_id = "213571"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Diplugem"
        severity = "91"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "html_loader.exe" ascii //weight: 1
        $x_1_2 = {8b 0f 33 4f 04 81 e1 ff ff ff 7f 33 0f 8d 7f 04 8b c1 24 01 0f b6 c0 f7 d8 1b c0 25 ?? ?? ?? ?? 33 87 ?? ?? ?? ?? d1 e9 33 c1 89 87 ?? ?? ?? ?? 4b 75}  //weight: 1, accuracy: Low
        $x_1_3 = {b9 04 01 00 00 29 c1 8d 84 45 d4 fb ff ff 89 4c 24 04 89 04 24 c7 44 24 0c 04 00 00 00 c7 44 24 08 ?? ?? ?? ?? e8 ?? ?? ?? ?? 89 34 24 ff 15 ?? ?? ?? ?? 83 ec 04 89 45 f0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Diplugem_213571_5
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Diplugem"
        threat_id = "213571"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Diplugem"
        severity = "91"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 49 01 29 c8 25 ff 00 00 00 88 c2 8b 45 ?? 89 c1 81 c1 01 00 00 00 89 4d ?? 88 10}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 52 01 29 d0 25 ff 00 00 00 88 c1 8b 45 ?? 89 c2 81 c2 01 00 00 00 89 55 ?? 88 08}  //weight: 1, accuracy: Low
        $x_1_3 = {89 e2 8d 75 ?? 89 72 0c 89 0a c7 42 08 40 00 00 00 c7 42 04 00 10 00 00 8b 0d ?? ?? ?? ?? 89 45 ?? ff d1 83 ec 10 8b 0d ?? ?? ?? ?? ba 00 10 00 00 8b 75 ?? 8b 7d ?? 89 34 24 89 7c 24 04 c7 44 24 08 00 10 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {c1 e9 02 fc f3 a5 8b 44 24 04 8b 64 24 08 89 44 24 20 9d 61 ff e0 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule BrowserModifier_Win32_Diplugem_213571_6
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Diplugem"
        threat_id = "213571"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Diplugem"
        severity = "91"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "& echo net start bits ^> nul >>" wide //weight: 1
        $x_1_2 = "temp\\winnie-pooh\\piglet-rules.tmp" wide //weight: 1
        $x_1_3 = "%you%\\Explorer\\%to%\\%idea%" ascii //weight: 1
        $x_1_4 = {8b c6 23 c7 f7 d8 25 20 83 b8 ed d1 ee 33 f0 49 75 ee}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule BrowserModifier_Win32_Diplugem_213571_7
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Diplugem"
        threat_id = "213571"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Diplugem"
        severity = "91"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "%stf%08x.%s" wide //weight: 1
        $x_1_2 = "\\__tmp_%08x" wide //weight: 1
        $x_1_3 = "{12DA0E6F-5543-440C-BAA2-28BF01070AFA}" wide //weight: 1
        $x_1_4 = {8b 4d 10 33 4d 18 89 4d 10 8b 55 14 0f af 55 10 89 55 14 8b 45 10 03 45 14 89 45 10 8b 4d 10 0f af 4d 1c 8b 55 fc 03 0a 8b 45 fc 89 08 eb ?? 8b e5 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Diplugem_213571_8
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Diplugem"
        threat_id = "213571"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Diplugem"
        severity = "91"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 44 18 01 89 d9 89 f9 81 f1 ff ff ff ff 81 e1 ff ff ff ff 89 d6 81 f6 ff ff ff ff 89 fb 21 f3 09 d9 81 f1 ff ff ff ff 89 c6 31 ce 21 c6}  //weight: 1, accuracy: High
        $x_1_2 = {8b 44 24 24 0d ?? ?? ?? ?? 21 c3 09 d9 89 f0 35 ff ff ff ff 25 ?? ?? ?? ?? 81 f2 ?? ?? ?? ?? 21 d6 89 cf 81 f7 ff ff ff ff 81 e7 ?? ?? ?? ?? 21 d1 09 f0 09 cf 31 f8 8b 8c 24 a8 00 00 00 8b 94 24 ac 00 00 00 88 04 0a}  //weight: 1, accuracy: Low
        $x_1_3 = {05 05 00 00 00 b9 04 00 00 00 8d 55 8c c7 45 8c 00 00 00 00 89 14 24 89 44 24 04 c7 44 24 08 04 00 00 00 e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? b9 01 00 00 00 e8 ?? ?? ?? ?? 89 14 24 c7 44 24 04 01 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Diplugem_213571_9
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Diplugem"
        threat_id = "213571"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Diplugem"
        severity = "91"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {50 6f 6c 69 63 69 65 73 20 7b [0-1] 0a 09 09 09 09 09 09 4e 6f 52 65 6d 6f 76 65 20 45 78 74 20 7b [0-1] 0a 09 09 09 09 09 09 09 4e 6f 52 65 6d 6f 76 65 20 43 4c 53 49 44 20 7b [0-1] 0a 09 09 09 09 09 09 09 09 76 61 6c 20 27 25 50 4c 55 47 49 4e 5f 43 4c 53 49 44 25 27 20 3d 20 73 20 27 31 27}  //weight: 2, accuracy: Low
        $x_1_2 = "<SCRIPT>eval(BgScript);</SCRIPT>" ascii //weight: 1
        $x_1_3 = "INI-enc:new(BASE64X|META)" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_Diplugem_213571_10
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Diplugem"
        threat_id = "213571"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Diplugem"
        severity = "91"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {b8 00 00 00 00 b9 0a 02 00 00 8d 54 24 ?? 8b 35 ?? ?? ?? ?? 89 b4 24 ?? ?? 00 00 89 14 24 c7 44 24 04 00 00 00 00 c7 44 24 08 0a 02 00 00 89 44 24 ?? 89 4c 24 ?? e8 ?? ?? ?? ?? b9 04 01 00 00 8d 54 24 ?? 89 14 24 c7 44 24 04 04 01 00 00 89 44 24 ?? 89 4c 24 ?? e8 ?? ?? ?? ?? 0f b7 4c 24 ?? 0f b7 54 24}  //weight: 10, accuracy: Low
        $x_1_2 = {b8 00 00 00 00 8b 8c 24 ?? ?? 00 00 89 c2 29 ca 89 c1 81 e9 01 00 00 00 01 ca 29 d0 89 84 24 ?? ?? 00 00 c7 84 24 ?? ?? 00 00 ?? ?? ?? ?? e9}  //weight: 1, accuracy: Low
        $x_1_3 = {0f b6 74 37 01 89 d7 81 f7 ff ff ff ff 89 f3 21 fb 81 f6 ff ff ff ff 21 f2 09 d3 88 da 8b b5 ?? ?? ?? ?? 8b bd ?? ?? ?? ?? 88 14 37}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_Diplugem_213571_11
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Diplugem"
        threat_id = "213571"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Diplugem"
        severity = "91"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "impaepofmnammebeenafgmllpnjaiime" wide //weight: 1
        $x_1_2 = "%appdata%\\appdataFr2.bin" wide //weight: 1
        $x_1_3 = {c7 45 fc 01 00 00 00 81 3d 04 62 02 10 8d c3 ab b9 74 16 89 13 89 53 04 89 53 08 89 55 90 89 55 94 89 55 98 e9 ff 01 00 00 81 3d 10 62 02 10 9e eb c4 a3 be 10 62 02 10 0f 85 cd 01 00 00 eb 06}  //weight: 1, accuracy: High
        $x_1_4 = {81 e2 03 00 00 80 79 05 4a 83 ca fc 42 8b 85 9c fe ff ff 8d 0c d5 00 00 00 00 d3 e8 43 30 06 42 46 3b df 72 db}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Diplugem_213571_12
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Diplugem"
        threat_id = "213571"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Diplugem"
        severity = "91"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "loader.gif" ascii //weight: 1
        $x_1_2 = "progressbar.gif" ascii //weight: 1
        $x_1_3 = {25 73 25 73 00 69 6d 61 67 65 73 00}  //weight: 1, accuracy: High
        $x_10_4 = "ForceRemove {F28C2F70-47DE-4EA5-8F6D-7D1476CD1EF5} = s 'TinyJSObject Class'" ascii //weight: 10
        $x_10_5 = "TypeLib = s '{7E77E9F2-D76B-4D54-B515-9A7F93DF03DF}'" ascii //weight: 10
        $x_10_6 = {8d 45 f8 50 ff 15 ?? ?? ?? ?? 8b 4d f8 8b 45 fc 6a 00 81 c1 00 80 c1 2a 68 80 96 98 00 15 21 4e 62 fe 50 51 e8 ?? ?? ?? ?? 83 fa 07 7c 0e 7f 07 3d ff 6f 40 93 76 05 83 c8 ff 8b d0 8b 4d 08 85 c9 74 05}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_Diplugem_213571_13
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Diplugem"
        threat_id = "213571"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Diplugem"
        severity = "91"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {33 00 38 00 2e 00 31 00 33 00 32 00 39 00 2e 00 25 00 64 00 2e 00 25 00 64 00 00 00}  //weight: 2, accuracy: High
        $x_2_2 = {25 00 61 00 70 00 70 00 64 00 61 00 74 00 61 00 25 00 5c 00 61 00 70 00 70 00 64 00 61 00 74 00 61 00 46 00 72 00 00 00}  //weight: 2, accuracy: High
        $x_2_3 = {25 00 61 00 70 00 70 00 64 00 61 00 74 00 61 00 25 00 5c 00 61 00 70 00 70 00 64 00 61 00 74 00 61 00 46 00 72 00 32 00 35 00 2e 00 62 00 69 00 6e 00 00 00}  //weight: 2, accuracy: High
        $x_1_4 = {2d 00 2d 00 65 00 78 00 74 00 65 00 6e 00 73 00 69 00 6f 00 6e 00 73 00 2d 00 6f 00 6e 00 2d 00 63 00 68 00 72 00 6f 00 6d 00 65 00 2d 00 75 00 72 00 6c 00 73 00 20 00 2d 00 2d 00 74 00 65 00 73 00 74 00 2d 00 74 00 79 00 70 00 65 00 20 00 2d 00 2d 00 73 00 69 00 6c 00 65 00 6e 00 74 00 2d 00 64 00 65 00 62 00 75 00 67 00 67 00 65 00 72 00 2d 00 65 00 78 00 74 00 65 00 6e 00 73 00 69 00 6f 00 6e 00 2d 00 61 00 70 00 69 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Diplugem_213571_14
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Diplugem"
        threat_id = "213571"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Diplugem"
        severity = "91"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 41 70 70 72 6f 76 65 64 45 78 74 65 6e 73 69 6f 6e 73 4d 69 67 72 61 74 69 6f 6e 5c 25 [0-84] 25}  //weight: 4, accuracy: Low
        $x_1_2 = "INI-enc:new(BASE64X|META)" wide //weight: 1
        $x_1_3 = "E=%d plgStorage::CreateInst" wide //weight: 1
        $x_1_4 = "setTimeout(function(){window.f();},2000);" wide //weight: 1
        $x_1_5 = "E:%d create memlog" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_Diplugem_213571_15
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Diplugem"
        threat_id = "213571"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Diplugem"
        severity = "91"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {69 c0 fd 43 03 00 05 c3 9e 26 00 25 ff ff ff 7f 83 7e 14 10 72 04 8b 16 eb 02 8b d6 8b c8 c1 f9 10 32 4c 1f 04 88 0c 3a 47 3b fd 72 d3}  //weight: 5, accuracy: High
        $x_1_2 = {5c 70 72 6f 64 75 63 74 69 6f 6e ?? 72 65 63 6f 6d 70 69 6c 65 [0-1] 5c 6d 75 6c 74 69 6e 73 74 61 6c 6c 65 72 5c [0-8] 5c 72 65 63 6f 6d 70 69 6c 65 5c ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5c 62 69 6e 5c 52 65 6c 65 61 73 65 2e 4d 69 6e 69 6d 61 6c 5c 64 6f 77 6e 6c 6f 61 64 65 72 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_3 = {5c 70 72 6f 64 75 63 74 69 6f 6e ?? 72 65 63 6f 6d 70 69 6c 65 [0-1] 5c 6d 75 6c 74 69 6e 73 74 61 6c 6c 65 72 5c [0-8] 5c 72 65 63 6f 6d 70 69 6c 65 5c ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5c 62 69 6e 5c 52 65 6c 65 61 73 65 2e 4d 69 6e 69 6d 61 6c 5c 72 75 6e 6e 65 72 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_4 = {5c 70 72 6f 64 75 63 74 69 6f 6e ?? 72 65 63 6f 6d 70 69 6c 65 [0-1] 5c 6d 75 6c 74 69 6e 73 74 61 6c 6c 65 72 5c [0-8] 5c 72 65 63 6f 6d 70 69 6c 65 5c ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5c 62 69 6e 5c 52 65 6c 65 61 73 65 2e 4d 69 6e 69 6d 61 6c 5c 6f 66 66 69 63 65 72 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_Diplugem_213571_16
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Diplugem"
        threat_id = "213571"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Diplugem"
        severity = "91"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 4c 24 34 89 4c 24 20 89 5c 24 24 8b 4c 24 38 ff d1 8b 84 24 b0 00 00 00 8b 8c 24 b4 00 00 00 03 41 09 89 84 24 a8 00 00 00 ff 94 24 a8 00 00 00 c7 44 24 7c ?? ?? ?? ?? e9 0d 00 00 00 b8 00 00 00 00 8d 65 f4 5e 5f 5b 5d c3}  //weight: 10, accuracy: Low
        $x_10_2 = {c7 84 24 b4 00 00 00 00 00 00 00 c7 84 24 b0 00 00 00 00 00 00 00 c7 84 24 ac 00 00 00 00 00 00 00 c7 84 24 a8 00 00 00 00 00 00 00 c7 84 24 a4 00 00 00 00 00 00 00 e8 ?? ?? ?? ?? 8d 0d 04 ?? ?? 00 89 84 24 ac 00 00 00 a1 ?? ?? ?? 00 8b 15 00 ?? ?? 00 8b b4 24 ac 00 00 00 89 34 24 89 54 24 04 89 4c 24 08 89 44 24 0c e8}  //weight: 10, accuracy: Low
        $x_1_3 = {89 0c 24 c7 44 24 04 01 00 00 00 89 84 24 ?? ?? 00 00 e8 ?? ?? ?? ?? 89 84 24 ?? ?? 00 00 8b 84 24 ?? ?? 00 00 89 84 24 ?? ?? 00 00 c7 84 24 ?? ?? 00 00 ?? ?? ?? ?? 8b 84 24 ?? ?? 00 00 89 c1 11 00 c7 84 24 ?? ?? 00 00 00 00 00 00 8b 0d 00 ?? ?? 00}  //weight: 1, accuracy: Low
        $x_1_4 = {b8 01 00 00 00 c7 44 24 74 00 00 00 00 8b 0d ?? ?? ?? ?? 89 0c 24 c7 44 24 04 01 00 00 00 89 44 24 60 e8 ?? ?? ?? ?? 89 44 24 74 8b 44 24 74 89 44 24 7c c7 44 24 64 ?? ?? ?? ?? 8b 44 24 64 89 c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_Diplugem_213571_17
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Diplugem"
        threat_id = "213571"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Diplugem"
        severity = "91"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "--startup=1" wide //weight: 1
        $x_1_2 = "GSyncMutant_%s%s" wide //weight: 1
        $x_1_3 = "Bidaily Synchronize Task" wide //weight: 1
        $x_1_4 = "\"last_server_activity\":\"%s\",\"last_client_activity\":\"%s\",\"tag_id\":\"%s\",\"is_admin\":\"%d\"" wide //weight: 1
        $x_1_5 = "\"installer_id\": \"%InstallerID%\",\"session_id\": \"%SessionID%\",\"affiliate_id\": \"%AffiliateID%\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Diplugem_213571_18
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Diplugem"
        threat_id = "213571"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Diplugem"
        severity = "91"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 3c 24 89 74 24 04 89 54 24 08 89 4c 24 0c 89 44 24 ?? e8 ?? ?? ?? ?? b8 04 00 00 00 8d 4c 24 ?? 8b 54 24 ?? 81 c2 05 00 00 00 89 0c 24 89 54 24 04 c7 44 24 08 04 00 00 00 89 44 24 ?? e8 ?? ?? ?? ?? b9 01 00 00 00 8b 54 24 ?? 89 14 24 c7 44 24 04 01 00 00 00 89 44 24 ?? 89 4c 24 ?? e8}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 84 24 b4 00 00 00 00 00 00 00 c7 84 24 b0 00 00 00 00 00 00 00 c7 84 24 ac 00 00 00 00 00 00 00 c7 84 24 a8 00 00 00 00 00 00 00 c7 84 24 a4 00 00 00 00 00 00 00 e8 ?? ?? ?? ?? 8d 0d ?? ?? ?? ?? 89 84 24 ac 00 00 00 a1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 8b b4 24 ac 00 00 00 89 34 24 89 54 24 04 89 4c 24 08 89 44 24 0c e8}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 40 05 89 e1 c7 41 0c 00 00 00 00 c7 41 04 00 00 00 00 c7 41 08 40 00 00 08 89 41 10 c7 41 14 00 00 00 00 c7 01 ff ff ff ff a1 ?? ?? ?? ?? ff d0 83 ec 18 89 84 24 ?? ?? 00 00 8b 84 24 ?? ?? 00 00 89 84 24 ?? ?? 00 00 c7 84 24 ?? ?? 00 00 ?? ?? ?? ?? 8b 84 24 84 00 00 00 89 c1}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 40 05 8b 8c 24 a0 00 00 00 89 e2 c7 42 0c 00 00 00 00 c7 42 08 00 00 00 00 89 0a 89 42 10 c7 42 04 3f 00 0f 00 a1 ?? ?? ?? ?? ff d0 83 ec 14 b9 ?? ?? ?? ?? ba ?? ?? ?? ?? 89 84 24 ?? ?? ?? ?? 81 bc 24 ?? ?? ?? ?? 00 00 00 00 0f 44 ca 89 8c 24 ?? ?? ?? ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Diplugem_213571_19
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Diplugem"
        threat_id = "213571"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Diplugem"
        severity = "91"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "InstallerEx_" ascii //weight: 5
        $x_5_2 = "ForceRemove {F28C2F70-47DE-4EA5-8F6D-7D1476CD1EF5} = s 'TinyJSObject Class'" ascii //weight: 5
        $x_1_3 = "GetWebBrowser/get_Document. (ptrDisp==%x, ptrBrowser==%x)" wide //weight: 1
        $x_1_4 = "CBrowserHost::Create. hwndParent=0x%x bMainWindow=%d" wide //weight: 1
        $x_1_5 = "IX_ExeFolder" wide //weight: 1
        $x_1_6 = "IX_DataFolder" wide //weight: 1
        $x_1_7 = "installer\\step0.ini" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_Diplugem_213571_20
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Diplugem"
        threat_id = "213571"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Diplugem"
        severity = "91"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2e 00 78 00 36 00 34 00 2e 00 64 00 6c 00 6c 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {42 00 48 00 4f 00 5f 00 75 00 6e 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 65 00 72 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {62 00 75 00 62 00 69 00 74 00 2e 00 64 00 6c 00 6c 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "DownAndExt" wide //weight: 1
        $x_1_5 = "No will completely remove <> extension." wide //weight: 1
        $x_1_6 = "will remove IE plugin from this folder" wide //weight: 1
        $x_1_7 = "install an alternate browser extension which will save you money while shopping online" wide //weight: 1
        $x_1_8 = "Cancel for abourt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule BrowserModifier_Win32_Diplugem_213571_21
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Diplugem"
        threat_id = "213571"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Diplugem"
        severity = "91"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 68 65 63 6b 69 6e 67 20 48 4b 4c 4d 5c 53 4f 46 54 57 41 52 45 5c [0-12] 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 55 6e 69 6e 73 74 61 6c 6c 5c 7b}  //weight: 1, accuracy: Low
        $x_1_2 = "installcollection.com/?HID=%HID%&BITS=%BITS%&PID=" ascii //weight: 1
        $x_1_3 = "CMlNA7l4rHa=iwJrjlFjj9hkl9" ascii //weight: 1
        $x_1_4 = "hy06BMFLgemXDftI=Azm9CdOLv" ascii //weight: 1
        $x_1_5 = "CzlGBa=Azm9CdOLv7VKC6mZByF" ascii //weight: 1
        $x_1_6 = {70 61 72 61 6d 00 00 00 64 6f 77 6e 6c 6f 61 64 5f 75 72 6c 00 00 00 00 25 48 49 44 25 00 00 00 25 50 49 44 25}  //weight: 1, accuracy: High
        $x_1_7 = {53 61 66 61 72 69 2f 35 33 37 2e 31 37 [0-21] 2e 65 78 65 00 00 00 00 25 78 5f 00 77 62}  //weight: 1, accuracy: Low
        $x_1_8 = "CMlNA7l4rn=iwJrjlFjj9hkl9" ascii //weight: 1
        $x_1_9 = {69 6e 73 74 61 6c 6c 63 6f 6c 6c 65 63 74 69 6f 6e 2e 63 6f 6d 2f 3f 48 49 44 3d [0-26] 26 42 49 54 53 3d 30 [0-2] 26 50 49 44 3d}  //weight: 1, accuracy: Low
        $x_1_10 = {25 42 49 54 53 25 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 70 61 72 61 6d 00 00 00 64 6f 77 6e 6c 6f 61 64 5f 75 72 6c}  //weight: 1, accuracy: Low
        $x_1_11 = {68 74 74 70 3a 2f 2f 64 6f 77 6e 6c 6f 61 64 2e [0-32] 2e [0-4] 2f 3f 65 3d}  //weight: 1, accuracy: Low
        $x_1_12 = "\\Uninstall\\{E7D895EF-039F-5F07-A148-D5E3BCF728D3}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule BrowserModifier_Win32_Diplugem_213571_22
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Diplugem"
        threat_id = "213571"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Diplugem"
        severity = "91"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {00 00 57 00 65 00 62 00 41 00 70 00 70 00 00 00}  //weight: 5, accuracy: High
        $x_5_2 = "ForceRemove {F28C2F70-47DE-4EA5-8F6D-7D1476CD1EF5} = s 'TinyJSObject Class'" ascii //weight: 5
        $x_1_3 = "images\\loader.gif" ascii //weight: 1
        $x_1_4 = "CreateHostWindow. hParent=0x%x bMainWin=%d" wide //weight: 1
        $x_1_5 = "CoCreateInstance(CLSID_TinyJSObject)" wide //weight: 1
        $x_1_6 = "if (typeof eret=='undefined') eret=document.createElement('div'); eret.id='eval_result'; document.appendChild(eret);" wide //weight: 1
        $x_1_7 = "m_webBrowser.QueryControl" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_Diplugem_213571_23
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Diplugem"
        threat_id = "213571"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Diplugem"
        severity = "91"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "/s /n /i:\"ExecuteCommands;UninstallCommands\" \"%s\"" wide //weight: 10
        $x_10_2 = "INI:enc INI-enc:new(BASE64X|META)Win32" wide //weight: 10
        $x_10_3 = "CRXDROP.EXE v%d.%d.%dr%" wide //weight: 10
        $x_10_4 = "_dlsys->%s is null" wide //weight: 10
        $x_1_5 = "Chrome.UninstallViaRegistry" wide //weight: 1
        $x_1_6 = "CEventLogger::LogEventV: vsprintf error %d with pszFormat='%s'" wide //weight: 1
        $x_1_7 = "AddExtensionToPrefs protected ret:%d" wide //weight: 1
        $x_1_8 = "CUninstaller::UninstallCommandline: UninstallString='%s'" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_Diplugem_213571_24
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Diplugem"
        threat_id = "213571"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Diplugem"
        severity = "91"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {57 00 65 00 62 00 41 00 70 00 70 00 00 00}  //weight: 5, accuracy: High
        $x_5_2 = "ForceRemove {F28C2F70-47DE-4EA5-8F6D-7D1476CD1EF5} = s 'TinyJSObject Class'" ascii //weight: 5
        $x_1_3 = "mini::ini_section::set_from_file: INI base64_decode'd OK '%s'" wide //weight: 1
        $x_1_4 = "mini::CDownloadJob::Wait: Waiting for job complete %d" wide //weight: 1
        $x_1_5 = "mini::CBITSDownloadJob::JobTransferred: Job Completed; job='%s'" wide //weight: 1
        $x_1_6 = "CInstallerApp::Start: after load screen" wide //weight: 1
        $x_1_7 = "CBrowserHost::CreateHostWindow: before CreateWebBrowser" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_Diplugem_213571_25
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Diplugem"
        threat_id = "213571"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Diplugem"
        severity = "91"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/s /n /i:\"ExecuteCommands;UninstallCommands\" \"%s\"" wide //weight: 1
        $x_1_2 = "mini::extended_mini_string<wchar_t>::base64_encode: E:%d libcode64::encode" wide //weight: 1
        $x_1_3 = "CFireFoxInstaller::RunFFCommand: (profile=%s,user=%s)" wide //weight: 1
        $x_1_4 = "CFireFoxInstaller::GetProfileNames:" wide //weight: 1
        $x_1_5 = "CGlobalContext::InstallUninstaller: : E:%d copy uninstaller DLL" wide //weight: 1
        $x_1_6 = "CIEInstaller::CIEInstallation::DumpToLog" wide //weight: 1
        $x_1_7 = "CUninstaller::UninstallCommandline: UninstallString='%s'" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule BrowserModifier_Win32_Diplugem_213571_26
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Diplugem"
        threat_id = "213571"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Diplugem"
        severity = "91"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {b8 00 00 00 00 b9 0a 00 00 00 8d 94 24 ?? ?? 00 00 be 10 00 00 00 8d bc 24 ?? ?? 00 00 8d 9c 24 ?? ?? 00 00 89 84 24 ?? ?? 00 00 b8 28 00 00 00 89 84 24 ?? ?? 00 00 8d 84 24 ?? ?? 00 00 89 84 24 ?? ?? 00 00 b8 c8 00 00 00 89 84 24 ?? ?? 00 00 8d 84 24 ?? ?? 00 00 89 84 24 ?? ?? 00 00 b8 0a 02 00 00 89 84 24 ?? ?? 00 00 8d 84 24 ?? ?? 00 00}  //weight: 10, accuracy: Low
        $x_10_2 = {89 04 24 c7 44 24 04 00 00 00 00 c7 44 24 08 3c 00 00 00 89 9c 24 ?? ?? 00 00 89 8c 24 ?? ?? 00 00 89 94 24 ?? ?? 00 00 89 b4 24 ?? ?? 00 00 89 bc 24 ?? ?? 00 00 e8 ?? ?? ?? ?? c7 84 24 ?? ?? 00 00 00 00 00 00 [0-22] 8b 84 24 ?? ?? 00 00 89 04 24 c7 44 24 04 00 00 00 00 c7 44 24 08 0a 02 00 00 e8}  //weight: 10, accuracy: Low
        $x_10_3 = {8d 45 f8 50 ff 15 ?? ?? ?? ?? 8b 4d f8 8b 45 fc 6a 00 81 c1 00 80 c1 2a 68 80 96 98 00 15 21 4e 62 fe 50 51 e8 ?? ?? ?? ?? 83 fa 07 7c 0e 7f 07 3d ff 6f 40 93 76 05 83 c8 ff 8b d0 8b 4d 08 85 c9 74 05}  //weight: 10, accuracy: Low
        $x_1_4 = {0f b6 44 38 01 89 f2 81 f2 ff ff ff ff 89 c7 21 d7 35 ff ff ff ff 21 c6 09 f7 89 f8 8b 95 ?? ?? ?? ?? 8b b5 ?? ?? ?? ?? 88 04 16}  //weight: 1, accuracy: Low
        $x_1_5 = {0f b6 74 37 01 89 d7 81 f7 ff ff ff ff 89 f3 21 fb 81 f6 ff ff ff ff 21 f2 09 d3 88 da 8b b5 ?? ?? ?? ?? 8b bd ?? ?? ?? ?? 88 14 37}  //weight: 1, accuracy: Low
        $x_1_6 = {0f b6 7c 3b 01 89 f3 81 f3 ff ff ff ff 81 e3 ?? ?? ?? ?? 81 f2 ?? ?? ?? ?? 21 d6 89 85 ?? ?? ?? ?? 89 f8 35 ff ff ff ff 25 ?? ?? ?? ?? 21 d7 09 f3 09 f8 31 c3 88 d8 8b 95 ?? ?? ?? ?? 8b b5 ?? ?? ?? ?? 88 04 16}  //weight: 1, accuracy: Low
        $x_1_7 = {0f b6 44 18 01 89 fe 81 f6 ff ff ff ff 81 e6 ?? ?? ?? ?? 81 f2 ?? ?? ?? ?? 21 d7 89 c3 81 f3 ff ff ff ff 81 e3 ?? ?? ?? ?? 21 d0 09 fe 09 c3 31 de 89 f0 8b 95 ?? ?? ?? ?? 8b b5 ?? ?? ?? ?? 88 04 16}  //weight: 1, accuracy: Low
        $x_1_8 = {0f b6 44 18 01 89 f9 81 f1 ff ff ff ff 81 e1 ?? ?? ?? ?? 81 f2 ?? ?? ?? ?? 21 d7 89 c6 81 f6 ff ff ff ff 81 e6 ?? ?? ?? ?? 21 d0 09 f9 09 c6 31 f1 88 c8 8b 8d ?? ?? ?? ?? 8b 95 ?? ?? ?? ?? 88 04 0a}  //weight: 1, accuracy: Low
        $x_1_9 = {ba 00 00 00 00 8b b5 ?? ?? ?? ?? 8b bd ?? ?? ?? ?? 0f b6 34 37 8b bd ?? ?? ?? ?? 81 ea 01 00 00 00 89 fb 29 d3 89 9d ?? ?? ?? ?? 8b [0-5] 0f b6 54 3a 01 89 f7 81 f7 ff ff ff ff 89 d3 21 fb 81 f2 ff ff ff ff 21 d6 09 f3 88 da 8b b5 ?? ?? ?? ?? 8b bd ?? ?? ?? ?? 88 14 37}  //weight: 1, accuracy: Low
        $x_1_10 = {0f b6 14 16 8b b5 ?? ?? ?? ?? 89 f7 81 c7 01 00 00 00 [0-6] 8b bd ?? ?? ?? ?? 0f b6 74 37 01 31 f2 88 d3 8b 95 [0-10] 88 1c 16 8b 95 ?? ?? ?? ?? 8b b5 ?? ?? ?? ?? 0f b6 36 39 f2 0f 44 c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_Diplugem_213571_27
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Diplugem"
        threat_id = "213571"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Diplugem"
        severity = "91"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mini::mutex::Init: E:%d create mutex '%s'" wide //weight: 1
        $x_1_2 = "Global\\{60430AFC-AA55-41bd-94C6-E2020CE1C711}" wide //weight: 1
        $x_1_3 = "CChromeBrandInstaller::CChromeBrandInstaller: Chrome mutex locked [this=%p]; Brand='%s'; Config.sDataDir='%s'" wide //weight: 1
        $x_1_4 = "CChromeBrandInstaller::PatchChromeDll: skipping folder %s; DLL not found" wide //weight: 1
        $x_1_5 = "CFireFoxInstaller::GetFFProfileINIPath: (%s): search profile.ini in '%s'" wide //weight: 1
        $x_1_6 = "CIEInstaller::CIEInstallation::LoadFromProfile: (%s): entry" wide //weight: 1
        $x_1_7 = "killall_fullpath: proc:'%s' idx:%d" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

