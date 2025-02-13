rule Rogue_Win32_FakeSmoke_141916_0
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeSmoke"
        threat_id = "141916"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSmoke"
        severity = "220"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {25 73 5c 25 73 20 53 6f 66 74 77 61 72 65 5c 25 73 2e 65 78 65 00}  //weight: 10, accuracy: High
        $x_10_2 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 74 20 2f 69 6d 20 25 73 2e 65 78 65 00}  //weight: 10, accuracy: High
        $x_1_3 = {31 2e 32 2e 30 2e 36 34 00}  //weight: 1, accuracy: High
        $x_1_4 = {32 2e 34 2e 30 2e 37 30 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeSmoke_141916_1
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeSmoke"
        threat_id = "141916"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSmoke"
        severity = "220"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 70 68 74 6d 6c 3f 67 65 74 3d fd 81 80 00 fe 25 25 5c [0-40] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_2 = {2f 54 52 41 4e 53 4c 41 54 45 32 00 64 6f 77 6e 6c 6f 61 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeSmoke_141916_2
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeSmoke"
        threat_id = "141916"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSmoke"
        severity = "220"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".html?get=" ascii //weight: 1
        $x_1_2 = {2f 54 52 41 4e 53 4c 41 54 45 32 00 64 6f 77 6e 6c 6f 61 64 00}  //weight: 1, accuracy: High
        $x_1_3 = "Virii Protection" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeSmoke_141916_3
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeSmoke"
        threat_id = "141916"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSmoke"
        severity = "220"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 14 39 03 c6 30 10 46 41 3b 74 24 10 72 e5}  //weight: 2, accuracy: High
        $x_1_2 = "%xspyware%d" ascii //weight: 1
        $x_1_3 = "%xsparse%d" ascii //weight: 1
        $x_1_4 = "id=%s&hash=" ascii //weight: 1
        $x_1_5 = "ArmorShield" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeSmoke_141916_4
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeSmoke"
        threat_id = "141916"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSmoke"
        severity = "220"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6f 77 6e 6c 6f 61 64 69 6e 67 20 57 69 6e [0-1] (42 6c 75 65 53 6f|46 69 67 68 74) 00}  //weight: 1, accuracy: Low
        $x_1_2 = "/download.php?s=" ascii //weight: 1
        $x_1_3 = "/download.php?p=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeSmoke_141916_5
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeSmoke"
        threat_id = "141916"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSmoke"
        severity = "220"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 53 65 63 75 72 69 74 79 20 53 65 72 76 69 63 65 00 49 6e 73 74 61 6c 6c 00 53 74 61 72 74 20 00 [0-25] 53 76 63 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_2 = {31 2e 32 2e 30 2e 36 33 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69 00}  //weight: 1, accuracy: High
        $x_1_3 = {56 69 73 69 74 20 74 68 65 20 [0-16] 20 73 69 74 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeSmoke_141916_6
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeSmoke"
        threat_id = "141916"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSmoke"
        severity = "220"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2e 68 74 6d 6c 3f 67 65 74 3d fd 81 80 00}  //weight: 10, accuracy: High
        $x_1_2 = {2f 54 52 41 4e 53 4c 41 54 45 00 64 6f 77 6e 6c 6f 61 64 00 fe 25 25 5c [0-40] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_3 = {2f 54 52 41 4e 53 4c 41 54 45 32 00 64 6f 77 6e 6c 6f 61 64 5f 71 75 69 65 74 00 fe 25 25 5c [0-40] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_4 = {2f 54 52 41 4e 53 4c 41 54 45 32 00 64 6f 77 6e 6c 6f 61 64 00 fe 25 25 5c [0-40] 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeSmoke_141916_7
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeSmoke"
        threat_id = "141916"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSmoke"
        severity = "220"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {63 6f 6b 69 65 73 68 6c 64 00}  //weight: 1, accuracy: High
        $x_1_2 = {6e 6f 61 64 77 61 72 65 34 5f 30 34 30 33 31 30 2e 6e 61 00}  //weight: 1, accuracy: High
        $x_1_3 = "Software\\Anti-Virus Elite" ascii //weight: 1
        $x_1_4 = "http://adwpro.avelite.hop.clickbank.net/?mode=p" wide //weight: 1
        $x_1_5 = {83 f8 ff bb 01 00 00 00 74 08 89 9e a0 01 00 00 eb 06 89 be a0 01 00 00 55 8b ce}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeSmoke_141916_8
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeSmoke"
        threat_id = "141916"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSmoke"
        severity = "220"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "{11b52b26-ebd3-4ace-a787-cc9f4fcbbd1e}" ascii //weight: 1
        $x_1_2 = "{eefb0c45-c8f9-45df-9564-7b6e8278f1fa}" ascii //weight: 1
        $x_1_3 = "91.212.127.135" ascii //weight: 1
        $x_1_4 = "SoftCop" ascii //weight: 1
        $x_1_5 = "www.soft-cop.com" ascii //weight: 1
        $x_1_6 = "/softcop.php?" ascii //weight: 1
        $x_1_7 = {25 73 73 3d 25 73 00}  //weight: 1, accuracy: High
        $x_1_8 = {25 73 70 3d 25 73 00}  //weight: 1, accuracy: High
        $x_1_9 = {25 73 64 31 3d 25 73 00}  //weight: 1, accuracy: High
        $x_1_10 = {47 45 54 00 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Rogue_Win32_FakeSmoke_141916_9
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeSmoke"
        threat_id = "141916"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSmoke"
        severity = "220"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_11_1 = {2e 68 74 6d 3f 67 65 74 3d fd 81 80 00 20 ff a8 80 00 2f 54 52 41 4e 53 4c 41 54 45 00 64 6f 77 6e 6c 6f 61 64 00 fe 25 25 5c [0-40] 2e 65 78 65}  //weight: 11, accuracy: Low
        $x_11_2 = {2e 70 68 70 3f 67 65 74 3d fd 81 80 00 20 ff a8 80 00 2f 54 52 41 4e 53 4c 41 54 45 00 64 6f 77 6e 6c 6f 61 64 00 fe 25 25 5c [0-40] 2e 65 78 65}  //weight: 11, accuracy: Low
        $x_10_3 = {2e 70 68 74 6d 6c 3f 67 65 74 3d fd 81 80 00}  //weight: 10, accuracy: High
        $x_1_4 = {2f 54 52 41 4e 53 4c 41 54 45 00 64 6f 77 6e 6c 6f 61 64 00 fe 25 25 5c [0-40] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_5 = {2f 54 52 41 4e 53 4c 41 54 45 32 00 64 6f 77 6e 6c 6f 61 64 5f 71 75 69 65 74 00 fe 25 25 5c [0-40] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_6 = {2f 54 52 41 4e 53 4c 41 54 45 32 00 64 6f 77 6e 6c 6f 61 64 00 fe 25 25 5c [0-40] 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_11_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeSmoke_141916_10
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeSmoke"
        threat_id = "141916"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSmoke"
        severity = "220"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "personnelles et l'extermination de votre machine." ascii //weight: 1
        $x_1_2 = "user_pref(\"general.useragent.extra.antispyapp\", \"%s\");" ascii //weight: 1
        $x_1_3 = "/update.php?t=prg&v=" ascii //weight: 1
        $x_1_4 = "Annoying advertisements wasting your traffic." ascii //weight: 1
        $x_1_5 = "Agressive Werbung Pop-ups" ascii //weight: 1
        $x_1_6 = "Register $ProgName$ to activate protection from malware attacks." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Rogue_Win32_FakeSmoke_141916_11
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeSmoke"
        threat_id = "141916"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSmoke"
        severity = "220"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 64 6e 6f 74 2d 61 2d 76 69 72 75 73 25 78 00}  //weight: 1, accuracy: High
        $x_1_2 = {25 64 73 70 61 6d 62 6f 74 25 78 00}  //weight: 1, accuracy: High
        $x_1_3 = {25 78 61 64 64 77 61 72 65 25 64 00}  //weight: 1, accuracy: High
        $x_1_4 = {53 6f 66 74 77 61 72 65 5c 48 61 72 6d 46 75 6c 6c 20 53 6f 66 74 77 61 72 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {25 73 2f 3f 63 75 72 72 65 6e 74 5f 76 65 72 73 69 6f 6e 3d 25 73 26 69 64 3d 25 73 00}  //weight: 1, accuracy: High
        $x_1_6 = {25 73 2f 72 65 70 6f 72 74 3f 69 64 3d 25 73 26 63 75 72 72 65 6e 74 5f 76 65 72 73 69 6f 6e 3d 00}  //weight: 1, accuracy: High
        $x_1_7 = "It can happend because this computer is infected by vir" wide //weight: 1
        $x_1_8 = "wscui.cpl" wide //weight: 1
        $x_1_9 = {33 c0 50 50 68 1f 00 02 00 50 50 56 68 01 00 00 80 8d 4d ?? 89 45 ?? e8 ?? ?? ?? ?? 85 c0 8b 7d ?? 75 18 6a 01 57 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Rogue_Win32_FakeSmoke_141916_12
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeSmoke"
        threat_id = "141916"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSmoke"
        severity = "220"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {42 6c 75 65 53 6f 66 74 20 ?? ?? ?? ?? ?? (2e|30|2d|39) (2e|30|2d|39)}  //weight: 1, accuracy: Low
        $x_1_2 = {53 65 74 75 70 3f 00 54 68 65 20 63 6f 72 65 20 66 69 6c 65 73 20 72 65 71 75 69 72 65 64 20 74 6f 20 75 73 65}  //weight: 1, accuracy: High
        $x_1_3 = {49 6e 73 74 61 6c 6c 69 6e 67 20 61 6e 64 20 75 73 69 6e 67 20 6f 66 20 74 68 65 20 53 6f 66 74 77 61 72 65 20 73 69 67 6e 69 66 69 65 73 20 74 68 65 20 55 73 65 72 20 61 63 63 65 70 74 02 00 61 6c 6c 20 63 6f 6e 64 69 74 69 6f 6e 73 20 6f 66 20 74 68 65 20 4c 69 63 65 6e 63 65 2e}  //weight: 1, accuracy: Low
        $x_1_4 = {41 6e 79 20 6f 66 20 61 66 6f 72 65 63 69 74 65 64 20 61 63 74 69 6f 6e 73 20 6e 65 65 64 20 77 72 69 74 74 65 6e 20 70 65 72 6d 69 73 73 69 6f 6e 20 6f 66 20 74 68 65 02 00 63 6f 70 79 72 69 67 68 74 20 6f 77 6e 65 72 2e}  //weight: 1, accuracy: Low
        $x_1_5 = {20 53 65 63 75 72 69 74 79 20 53 65 72 76 69 63 65 00 49 6e 73 74 61 6c 6c 00 53 74 61 72 74 20 00 [0-25] 53 76 63 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_6 = {2d 20 4e 6f 20 70 65 72 73 6f 6e 20 6f 72 20 63 6f 6d 70 61 6e 79 20 6d 61 79 20 64 69 73 74 72 69 62 75 74 65 20 64 69 73 69 6e 74 65 67 72 61 74 65 64 20 70 61 72 74 73 10 00 6f 66 20 74 68 65 20 70 61 63 6b 61 67 65 2e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Rogue_Win32_FakeSmoke_141916_13
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeSmoke"
        threat_id = "141916"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSmoke"
        severity = "220"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {83 f8 64 72 ?? 5f c7 86 06 02 00 00 77 66 44 55 c7 06 45 47 46 45}  //weight: 4, accuracy: Low
        $x_2_2 = "__SIGN_THIS_FILE_IS_INFECTED" ascii //weight: 2
        $x_2_3 = "_SAY_MAGIC_WORD_:_DELETE_" ascii //weight: 2
        $x_2_4 = "http://%s/protection/?i=%s" ascii //weight: 2
        $x_2_5 = "_work\\VProtector\\Release\\" ascii //weight: 2
        $x_1_6 = "Harmful memory infection was detected." wide //weight: 1
        $x_1_7 = "Your computer is infected with spyware.It could damage your critical files" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            ((1 of ($x_4_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeSmoke_141916_14
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeSmoke"
        threat_id = "141916"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSmoke"
        severity = "220"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "svc.exe [-install] | [-uninstall] | [-svc]" ascii //weight: 2
        $x_2_2 = {2d 63 6f 6e 73 6f 6c 65 00}  //weight: 2, accuracy: High
        $x_1_3 = {00 41 6e 74 69 73 70 79 53 76 63 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 25 73 20 25 73 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 25 73 25 30 38 58 25 30 38 58 00}  //weight: 1, accuracy: High
        $x_1_6 = {2f 75 70 64 61 74 65 2e 70 68 70 3f 74 3d 70 72 67 26 76 3d 00}  //weight: 1, accuracy: High
        $x_1_7 = {2f 75 70 64 61 74 65 2e 70 68 70 3f 74 3d 64 61 74 26 76 3d 00}  //weight: 1, accuracy: High
        $x_1_8 = {43 41 6e 74 69 53 70 79 43 6f 72 65 00}  //weight: 1, accuracy: High
        $x_2_9 = "user_pref(\"general.useragent.extra.antispyapp\", \"%s\");" ascii //weight: 2
        $x_1_10 = "-url \"%s%s?%s%s&id=" ascii //weight: 1
        $x_1_11 = {73 79 73 74 65 6d 5f 73 63 61 6e 5f 6f 6e 5f 73 74 61 72 74 75 70 00}  //weight: 1, accuracy: High
        $x_1_12 = {6c 61 73 74 5f 73 63 61 6e 00}  //weight: 1, accuracy: High
        $x_1_13 = {69 6e 74 65 72 6e 65 74 5f 61 67 65 6e 74 73 00}  //weight: 1, accuracy: High
        $x_1_14 = "Register $ProgName$ to activate protection from malware attacks." ascii //weight: 1
        $x_1_15 = "Annoying advertisements wasting your traffic." ascii //weight: 1
        $x_1_16 = "Agressive Werbung Pop-ups" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeSmoke_141916_15
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeSmoke"
        threat_id = "141916"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSmoke"
        severity = "220"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "may lead to the leak of your personal data and the extermination of your machine" wide //weight: 1
        $x_1_2 = "user_pref(\"general.useragent.extra.antispyapp\", \"%s\");" ascii //weight: 1
        $x_1_3 = "/update.php?t=prg&v=" ascii //weight: 1
        $x_1_4 = "with no risk of infection for you PC." wide //weight: 1
        $x_1_5 = {41 00 67 00 72 00 65 00 73 00 73 00 69 00 76 00 65 00 20 00 61 00 64 00 76 00 65 00 72 00 74 00 69 00 73 00 69 00 6e 00 67 00 20 00 70 00 6f 00 70 00 75 00 70 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = "Enable data exchange for AntiSpyUI server" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Rogue_Win32_FakeSmoke_141916_16
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeSmoke"
        threat_id = "141916"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSmoke"
        severity = "220"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {26 43 6c 6f 73 65 00 53 61 66 65 46 69 67 68 74 65 72 20 31 2e 32 2e 30 2e 36 33 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_2 = {26 43 6c 6f 73 65 00 54 72 75 73 74 43 6f 70 20 31 2e 32 2e 30 2e 36 33 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_3 = {26 43 6c 6f 73 65 00 54 72 75 73 74 53 6f 6c 64 69 65 72 20 31 2e 32 2e 30 2e 36 33 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_4 = {26 43 6c 6f 73 65 00 54 72 75 73 74 46 69 67 68 74 65 72 20 31 2e 32 2e 30 2e 36 33 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_5 = {26 43 6c 6f 73 65 00 53 6f 66 74 53 6f 6c 64 69 65 72 20 31 2e 32 2e 30 2e 36 33 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_6 = {26 43 6c 6f 73 65 00 53 6f 66 74 43 6f 70 20 31 2e 32 2e 30 2e 36 33 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_7 = {26 43 6c 6f 73 65 00 54 52 45 20 41 6e 74 69 56 69 72 75 73 20 32 2e 30 2e 30 2e 31 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_8 = {26 43 6c 6f 73 65 00 53 6f 66 74 56 65 74 65 72 61 6e 20 31 2e 32 2e 30 2e 36 33 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_9 = {26 43 6c 6f 73 65 00 53 6f 66 74 53 74 72 6f 6e 67 68 6f 6c 64 20 31 2e 32 2e 30 2e 36 33 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_10 = {26 43 6c 6f 73 65 00 53 68 69 65 6c 64 53 61 66 65 6e 65 73 73 20 31 2e 32 2e 30 2e 36 33 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_11 = {26 43 6c 6f 73 65 00 53 6f 66 74 42 61 72 72 69 65 72 20 31 2e 32 2e 30 2e 36 33 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_12 = {26 43 6c 6f 73 65 00 42 6c 6f 63 6b 57 61 74 63 68 65 72 20 31 2e 32 2e 30 2e 36 33 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_13 = {26 43 6c 6f 73 65 00 42 6c 6f 63 6b 53 63 61 6e 6e 65 72 20 31 2e 32 2e 30 2e 36 33 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_14 = {26 43 6c 6f 73 65 00 41 6e 74 69 41 49 44 20 31 2e 32 2e 30 2e 36 33 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_15 = {26 43 6c 6f 73 65 00 4c 69 6e 6b 53 61 66 65 6e 65 73 73 20 31 2e 32 2e 30 2e 36 33 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_16 = {26 43 6c 6f 73 65 00 53 69 74 65 56 69 6c 6c 61 69 6e 20 31 2e 32 2e 30 2e 36 33 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_17 = {26 43 6c 6f 73 65 00 53 65 63 75 72 65 4b 65 65 70 65 72 20 31 2e 32 2e 30 2e 36 33 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_18 = {26 43 6c 6f 73 65 00 4b 65 65 70 43 6f 70 20 31 2e 32 2e 30 2e 36 33 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_19 = {26 43 6c 6f 73 65 00 52 45 41 6e 74 69 20 31 2e 32 2e 30 2e 36 33 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_20 = {26 43 6c 6f 73 65 00 52 45 53 70 79 57 61 72 65 20 31 2e 32 2e 30 2e 36 33 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_21 = {26 43 6c 6f 73 65 00 41 6e 74 69 41 64 64 20 31 2e 32 2e 30 2e 36 33 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_22 = {26 43 6c 6f 73 65 00 41 6e 74 69 4b 65 65 70 20 31 2e 32 2e 30 2e 36 33 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_23 = {26 43 6c 6f 73 65 00 41 6e 74 69 54 72 6f 79 20 31 2e 32 2e 30 2e 36 33 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_24 = {26 43 6c 6f 73 65 00 53 69 74 65 41 64 77 61 72 65 20 31 2e 32 2e 30 2e 36 33 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_25 = {26 43 6c 6f 73 65 00 49 47 75 61 72 64 50 63 20 31 2e 32 2e 30 2e 36 33 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_26 = {26 43 6c 6f 73 65 00 47 75 61 72 64 50 63 73 20 31 2e 32 2e 30 2e 36 33 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_27 = {26 43 6c 6f 73 65 00 54 68 65 44 65 66 65 6e 64 20 31 2e 32 2e 30 2e 36 33 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_28 = {26 43 6c 6f 73 65 00 53 79 73 44 65 66 65 6e 63 65 20 31 2e 32 2e 30 2e 36 33 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_29 = {26 43 6c 6f 73 65 00 50 72 6f 74 65 63 74 50 63 73 20 31 2e 32 2e 30 2e 36 33 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_30 = {26 43 6c 6f 73 65 00 41 50 43 50 72 6f 74 65 63 74 20 31 2e 32 2e 30 2e 36 33 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_31 = {26 43 6c 6f 73 65 00 47 72 65 61 74 44 65 66 65 6e 64 65 72 20 32 2e 32 2e 30 2e 35 33 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_32 = {26 43 6c 6f 73 65 00 50 63 73 50 72 6f 74 65 63 74 6f 72 20 32 2e 32 2e 30 2e 35 33 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_33 = {50 43 70 72 6f 74 65 63 74 61 72 20 32 2e 32 2e 30 2e 35 33 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_34 = {41 50 63 44 65 66 65 6e 64 65 72 20 32 2e 32 2e 30 2e 35 33 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_35 = {53 79 73 50 72 6f 74 65 63 74 6f 72 20 32 2e 32 2e 30 2e 35 33 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_36 = {49 6e 53 79 73 53 65 63 75 72 65 20 32 2e 32 2e 30 2e 35 33 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_37 = {53 79 73 44 65 66 65 6e 64 65 72 73 20 32 2e 32 2e 30 2e 35 33 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_38 = {26 43 6c 6f 73 65 00 44 65 66 65 6e 64 41 50 63 20 32 2e 32 2e 30 2e 35 33 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_39 = {26 43 6c 6f 73 65 00 41 50 63 53 65 63 75 72 65 20 32 2e 32 2e 30 2e 35 33 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_40 = {26 43 6c 6f 73 65 00 50 63 73 53 65 63 75 72 65 20 32 2e 32 2e 30 2e 35 33 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_41 = {26 43 6c 6f 73 65 00 41 50 63 53 61 66 65 20 32 2e 32 2e 30 2e 35 33 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_42 = {26 43 6c 6f 73 65 00 50 63 53 65 63 75 72 65 4e 65 74 20 32 2e 32 2e 30 2e 35 33 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_43 = {26 43 6c 6f 73 65 00 4d 79 50 63 53 65 63 75 72 65 20 32 2e 32 2e 30 2e 35 33 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_44 = {26 43 6c 6f 73 65 00 47 75 61 72 64 57 57 57 20 32 2e 32 2e 30 2e 35 33 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_45 = {26 43 6c 6f 73 65 00 53 61 66 65 50 63 41 76 20 32 2e 32 2e 30 2e 35 33 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_46 = {26 43 6c 6f 73 65 00 53 65 63 75 72 65 50 63 41 76 20 32 2e 32 2e 30 2e 35 33 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Rogue_Win32_FakeSmoke_141916_17
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeSmoke"
        threat_id = "141916"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSmoke"
        severity = "220"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 6c 69 63 6b 20 4e 65 78 74 20 74 6f 20 63 6f 6e 74 69 6e 75 65 2e 00 26 43 6c 6f 73 65 00 53 61 (76 65|66 65) 4b 65 65 70 65 72 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: Low
        $x_1_2 = {43 6c 69 63 6b 20 4e 65 78 74 20 74 6f 20 63 6f 6e 74 69 6e 75 65 2e 00 26 43 6c 6f 73 65 00 53 6f 66 74 53 61 66 65 6e 65 73 73 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_3 = {43 6c 69 63 6b 20 4e 65 78 74 20 74 6f 20 63 6f 6e 74 69 6e 75 65 2e 00 26 43 6c 6f 73 65 00 54 72 75 73 74 57 61 72 72 69 6f 72 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_4 = {43 6c 69 63 6b 20 4e 65 78 74 20 74 6f 20 63 6f 6e 74 69 6e 75 65 2e 00 26 43 6c 6f 73 65 00 53 61 76 65 44 65 66 65 6e 64 65 72 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_5 = {43 6c 69 63 6b 20 4e 65 78 74 20 74 6f 20 63 6f 6e 74 69 6e 75 65 2e 00 26 43 6c 6f 73 65 00 53 61 76 65 41 72 6d 6f 72 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_6 = {43 6c 69 63 6b 20 4e 65 78 74 20 74 6f 20 63 6f 6e 74 69 6e 75 65 2e 00 26 43 6c 6f 73 65 00 53 65 63 75 72 69 74 79 46 69 67 68 74 65 72 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_7 = {43 6c 69 63 6b 20 4e 65 78 74 20 74 6f 20 63 6f 6e 74 69 6e 75 65 2e 00 26 43 6c 6f 73 65 00 53 65 63 75 72 65 56 65 74 65 72 61 6e 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_8 = {43 6c 69 63 6b 20 4e 65 78 74 20 74 6f 20 63 6f 6e 74 69 6e 75 65 2e 00 26 43 6c 6f 73 65 00 53 65 63 75 72 69 74 79 53 6f 6c 64 69 65 72 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_9 = {43 6c 69 63 6b 20 4e 65 78 74 20 74 6f 20 63 6f 6e 74 69 6e 75 65 2e 00 26 43 6c 6f 73 65 00 53 65 63 75 72 65 57 61 72 72 69 6f 72 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_10 = {43 6c 69 63 6b 20 4e 65 78 74 20 74 6f 20 63 6f 6e 74 69 6e 75 65 2e 00 26 43 6c 6f 73 65 00 54 72 75 73 74 43 6f 70 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_11 = {43 6c 69 63 6b 20 4e 65 78 74 20 74 6f 20 63 6f 6e 74 69 6e 75 65 2e 00 26 43 6c 6f 73 65 00 53 65 63 75 72 65 46 69 67 68 74 65 72 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_12 = {43 6c 69 63 6b 20 4e 65 78 74 20 74 6f 20 63 6f 6e 74 69 6e 75 65 2e 00 26 43 6c 6f 73 65 00 41 6e 74 69 41 49 44 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_13 = {43 6c 69 63 6b 20 4e 65 78 74 20 74 6f 20 63 6f 6e 74 69 6e 75 65 2e 00 26 43 6c 6f 73 65 00 4c 69 6e 6b 53 61 66 65 6e 65 73 73 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_14 = {43 6c 69 63 6b 20 4e 65 78 74 20 74 6f 20 63 6f 6e 74 69 6e 75 65 2e 00 26 43 6c 6f 73 65 00 53 69 74 65 56 69 6c 6c 61 69 6e 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_15 = {43 6c 69 63 6b 20 4e 65 78 74 20 74 6f 20 63 6f 6e 74 69 6e 75 65 2e 00 26 43 6c 6f 73 65 00 53 65 63 75 72 65 4b 65 65 70 65 72 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_16 = {43 6c 69 63 6b 20 4e 65 78 74 20 74 6f 20 63 6f 6e 74 69 6e 75 65 2e 00 26 43 6c 6f 73 65 00 4b 65 65 70 43 6f 70 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_17 = {43 6c 69 63 6b 20 4e 65 78 74 20 74 6f 20 63 6f 6e 74 69 6e 75 65 2e 00 26 43 6c 6f 73 65 00 52 45 41 6e 74 69 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_18 = {43 6c 69 63 6b 20 4e 65 78 74 20 74 6f 20 63 6f 6e 74 69 6e 75 65 2e 00 26 43 6c 6f 73 65 00 52 45 53 70 79 57 61 72 65 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_19 = {43 6c 69 63 6b 20 4e 65 78 74 20 74 6f 20 63 6f 6e 74 69 6e 75 65 2e 00 26 43 6c 6f 73 65 00 41 6e 74 69 41 64 64 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_20 = {43 6c 69 63 6b 20 4e 65 78 74 20 74 6f 20 63 6f 6e 74 69 6e 75 65 2e 00 26 43 6c 6f 73 65 00 41 6e 74 69 4b 65 65 70 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_21 = {43 6c 69 63 6b 20 4e 65 78 74 20 74 6f 20 63 6f 6e 74 69 6e 75 65 2e 00 26 43 6c 6f 73 65 00 41 6e 74 69 54 72 6f 79 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_22 = {43 6c 69 63 6b 20 4e 65 78 74 20 74 6f 20 63 6f 6e 74 69 6e 75 65 2e 00 26 43 6c 6f 73 65 00 53 69 74 65 41 64 77 61 72 65 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_23 = {43 6c 69 63 6b 20 4e 65 78 74 20 74 6f 20 63 6f 6e 74 69 6e 75 65 2e 00 26 43 6c 6f 73 65 00 49 47 75 61 72 64 50 63 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_24 = {43 6c 69 63 6b 20 4e 65 78 74 20 74 6f 20 63 6f 6e 74 69 6e 75 65 2e 00 26 43 6c 6f 73 65 00 47 75 61 72 64 50 63 73 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_25 = {43 6c 69 63 6b 20 4e 65 78 74 20 74 6f 20 63 6f 6e 74 69 6e 75 65 2e 00 26 43 6c 6f 73 65 00 54 68 65 44 65 66 65 6e 64 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_26 = {43 6c 69 63 6b 20 4e 65 78 74 20 74 6f 20 63 6f 6e 74 69 6e 75 65 2e 00 26 43 6c 6f 73 65 00 53 79 73 44 65 66 65 6e 63 65 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_27 = {43 6c 69 63 6b 20 4e 65 78 74 20 74 6f 20 63 6f 6e 74 69 6e 75 65 2e 00 26 43 6c 6f 73 65 00 50 72 6f 74 65 63 74 50 63 73 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_28 = {43 6c 69 63 6b 20 4e 65 78 74 20 74 6f 20 63 6f 6e 74 69 6e 75 65 2e 00 26 43 6c 6f 73 65 00 41 50 43 50 72 6f 74 65 63 74 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_29 = {43 6c 69 63 6b 20 4e 65 78 74 20 74 6f 20 63 6f 6e 74 69 6e 75 65 2e 00 26 43 6c 6f 73 65 00 47 72 65 61 74 44 65 66 65 6e 64 65 72 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_30 = {43 6c 69 63 6b 20 4e 65 78 74 20 74 6f 20 63 6f 6e 74 69 6e 75 65 2e 00 26 43 6c 6f 73 65 00 50 63 73 50 72 6f 74 65 63 74 6f 72 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_31 = {43 6c 69 63 6b 20 4e 65 78 74 20 74 6f 20 63 6f 6e 74 69 6e 75 65 2e 00 26 43 6c 6f 73 65 00 50 43 70 72 6f 74 65 63 74 61 72 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_32 = {43 6c 69 63 6b 20 4e 65 78 74 20 74 6f 20 63 6f 6e 74 69 6e 75 65 2e 00 26 43 6c 6f 73 65 00 41 50 63 44 65 66 65 6e 64 65 72 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_33 = {43 6c 69 63 6b 20 4e 65 78 74 20 74 6f 20 63 6f 6e 74 69 6e 75 65 2e 00 26 43 6c 6f 73 65 00 53 79 73 50 72 6f 74 65 63 74 6f 72 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_34 = {43 6c 69 63 6b 20 4e 65 78 74 20 74 6f 20 63 6f 6e 74 69 6e 75 65 2e 00 26 43 6c 6f 73 65 00 49 6e 53 79 73 53 65 63 75 72 65 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_35 = {43 6c 69 63 6b 20 4e 65 78 74 20 74 6f 20 63 6f 6e 74 69 6e 75 65 2e 00 26 43 6c 6f 73 65 00 53 79 73 44 65 66 65 6e 64 65 72 73 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_36 = {43 6c 69 63 6b 20 4e 65 78 74 20 74 6f 20 63 6f 6e 74 69 6e 75 65 2e 00 26 43 6c 6f 73 65 00 44 65 66 65 6e 64 41 50 63 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_37 = {43 6c 69 63 6b 20 4e 65 78 74 20 74 6f 20 63 6f 6e 74 69 6e 75 65 2e 00 26 43 6c 6f 73 65 00 41 50 63 53 65 63 75 72 65 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_38 = {43 6c 69 63 6b 20 4e 65 78 74 20 74 6f 20 63 6f 6e 74 69 6e 75 65 2e 00 26 43 6c 6f 73 65 00 50 63 73 53 65 63 75 72 65 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_39 = {43 6c 69 63 6b 20 4e 65 78 74 20 74 6f 20 63 6f 6e 74 69 6e 75 65 2e 00 26 43 6c 6f 73 65 00 41 50 63 53 61 66 65 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_40 = {43 6c 69 63 6b 20 4e 65 78 74 20 74 6f 20 63 6f 6e 74 69 6e 75 65 2e 00 26 43 6c 6f 73 65 00 50 63 53 65 63 75 72 65 4e 65 74 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_41 = {43 6c 69 63 6b 20 4e 65 78 74 20 74 6f 20 63 6f 6e 74 69 6e 75 65 2e 00 26 43 6c 6f 73 65 00 4d 79 50 63 53 65 63 75 72 65 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_42 = {43 6c 69 63 6b 20 4e 65 78 74 20 74 6f 20 63 6f 6e 74 69 6e 75 65 2e 00 26 43 6c 6f 73 65 00 47 75 61 72 64 57 57 57 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_43 = {43 6c 69 63 6b 20 4e 65 78 74 20 74 6f 20 63 6f 6e 74 69 6e 75 65 2e 00 26 43 6c 6f 73 65 00 53 61 66 65 50 63 41 76 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_44 = {43 6c 69 63 6b 20 4e 65 78 74 20 74 6f 20 63 6f 6e 74 69 6e 75 65 2e 00 26 43 6c 6f 73 65 00 53 65 63 75 72 65 50 63 41 76 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
        $x_1_45 = {3a 20 43 6f 6d 70 6c 65 74 65 64 00 26 43 6c 6f 73 65 00 56 69 72 75 73 50 72 6f 74 65 63 74 6f 72 00 fe 24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

