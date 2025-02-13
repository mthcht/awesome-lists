rule Backdoor_Win32_Afcore_2147597756_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Afcore"
        threat_id = "2147597756"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Afcore"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "INSTALL_BASE" ascii //weight: 1
        $x_1_2 = "*\\intern*\\iexplore.exe" ascii //weight: 1
        $x_1_3 = "Octopus PID: %d(%i)" ascii //weight: 1
        $x_1_4 = "day %d has elapsed" ascii //weight: 1
        $x_1_5 = "wanted process (%s), level=%d" ascii //weight: 1
        $x_1_6 = "IPC (%d), log (%d) or hook (%d)" ascii //weight: 1
        $x_1_7 = "OCTOPUS_SHARED (pid: %d)" ascii //weight: 1
        $x_1_8 = "%s=%s Comment: %s Flags: %h" ascii //weight: 1
        $x_1_9 = "browser rule %d has been associated" ascii //weight: 1
        $x_1_10 = "**END OF PIPE" ascii //weight: 1
        $x_1_11 = "of %d files listed in %s." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule Backdoor_Win32_Afcore_I_2147608793_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Afcore.I"
        threat_id = "2147608793"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Afcore"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {76 16 8b ca 33 4c 24 08 03 c1 8b c8 83 e1 0f 42 d3 c8 3b 54 24 04 72 ea}  //weight: 1, accuracy: High
        $x_1_2 = {63 6c 65 61 6e 75 70 00 69 6e 69 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Afcore_CE_2147609806_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Afcore.CE"
        threat_id = "2147609806"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Afcore"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff ff 59 89 45 ?? 59 c1 e8 08 33 c9 8b d1 83 e2 03 02 44 15 ?? 30 81 ?? ?? ?? ?? 41 81 f9 ?? ?? ?? 00 72 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {75 08 8b f1 33 74 24 0c 03 c6 03 c2 41 83 c2 06 3b 4c 24 08 72 e8}  //weight: 1, accuracy: High
        $x_1_3 = {ff d0 68 00 80 00 00 6a 00 ff 35 ?? ?? ?? ?? ff 55 b8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Afcore_B_2147611849_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Afcore.gen!B"
        threat_id = "2147611849"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Afcore"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {74 16 6a 01 57 ff 56 34 33 c9 3b c1 74 06 51 53 51 51 ff d0 57 ff 56 30}  //weight: 4, accuracy: High
        $x_3_2 = {68 00 30 10 00 ff 03 01 01 01 33 36 37}  //weight: 3, accuracy: Low
        $x_1_3 = {ff d0 68 00 80 00 00 6a 00 ff 35 ?? ?? ?? 10 ff 55 ?? ?? ?? ?? 8a 45 ?? c9}  //weight: 1, accuracy: Low
        $x_1_4 = {30 40 00 ff 55 ?? 6a 00 ff 15 ?? 20 40 00 0c 00 ff ?? 68 00 80 00 00 6a 00 ff 35}  //weight: 1, accuracy: Low
        $x_1_5 = {8b d1 83 e2 03 02 44 15 ?? 30 81}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Afcore_M_2147616308_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Afcore.M"
        threat_id = "2147616308"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Afcore"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {f3 a4 c7 07 2e 64 ?? 6c c6 47 04 00 6a 01 68 00 00 00 c0}  //weight: 2, accuracy: Low
        $x_2_2 = {83 c3 07 8b 45 0c 89 45 fc 6a 10 8d 4d f0 b8 78 56 34 12}  //weight: 2, accuracy: High
        $x_2_3 = {74 0a d1 e9 81 f1 ?? ?? ?? ?? eb 02 d1 e9 4e 75}  //weight: 2, accuracy: Low
        $x_1_4 = {ff ff 80 bd eb fe ff ff 61 72 06 6a 7a 6a 61 eb 04 6a 5a 6a 41}  //weight: 1, accuracy: High
        $x_1_5 = {6a 40 ff 75 f0 ff d6 6a f1 ff 75 f4 ff d7 ff 75 f4}  //weight: 1, accuracy: High
        $x_1_6 = "AFCORE_BASE" ascii //weight: 1
        $x_1_7 = "*\\intern*\\iexplore.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Afcore_C_2147616920_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Afcore.gen!C"
        threat_id = "2147616920"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Afcore"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {74 16 6a 01 57 ff 56 70 33 c9 3b c1 74 06 51 53 51 51 ff d0 57 ff 56 18}  //weight: 2, accuracy: High
        $x_1_2 = {68 00 30 10 00 ff 75 ?? 6a 00 ff 15 (14|10)}  //weight: 1, accuracy: Low
        $x_1_3 = {8a 0c 01 32 04 01 01 04 04 0a 0e 4a ?? 4e ?? [0-3] 88 0c 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Afcore_E_2147626621_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Afcore.gen!E"
        threat_id = "2147626621"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Afcore"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {68 00 30 10 00 ff 76 ?? 6a 00 ff 15 03 05 05 05 13 00 e9 10 00 eb 10 00 75}  //weight: 2, accuracy: Low
        $x_1_2 = {8a 4c 01 28 32 4e ?? 8b 56 ?? 88 0c 10}  //weight: 1, accuracy: Low
        $x_1_3 = {8a 0c 01 32 4e ?? 8b 56 ?? 88 0c 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Afcore_F_2147629730_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Afcore.gen!F"
        threat_id = "2147629730"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Afcore"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {74 0c 6a 01 53 53 53 ff 55 f8 57 ff 56 70 8d 85 ?? ?? ?? ?? 50 ff 56 50}  //weight: 3, accuracy: Low
        $x_2_2 = {68 00 30 10 00 ff 03 01 04 04 36 76 ?? b6 ?? ?? ?? ?? 6a 00 ff 15}  //weight: 2, accuracy: Low
        $x_1_3 = {8a 4c 01 28 32 (0e|4e ??) 02 05 05 8b 56 ?? 8b 96 ?? ?? ?? ?? 88 0c 10}  //weight: 1, accuracy: Low
        $x_1_4 = {8a 54 0a 28 8b 7e ?? 8d 86 ?? ?? ?? ?? 32 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Afcore_G_2147636891_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Afcore.gen!G"
        threat_id = "2147636891"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Afcore"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {eb 1c 81 2d ?? ?? ?? ?? 33 03 00 00 6a 00 6a 00 68 00 04 00 00 ff 75 08 ff 15 ?? ?? ?? ?? 33 c0 c9 c2 10 00}  //weight: 10, accuracy: Low
        $x_1_2 = {68 00 30 10 00 ff 76 ?? 6a 00 ff 15 03 05 05 05 13 00 e9 10 00 eb 10 00 75}  //weight: 1, accuracy: Low
        $x_1_3 = {68 00 30 10 00 ff b6 ?? ?? ?? ?? 6a 00 ff 15 03 05 05 05 16 00 e9 13 00 eb 13 00 75}  //weight: 1, accuracy: Low
        $x_1_4 = {b8 00 30 10 00 50 56 6a 00 89 45 ?? ff 15 40 00 6a 40 5f}  //weight: 1, accuracy: Low
        $x_1_5 = {be 00 30 10 00 [0-32] 6a 40 56 57 33 f6 56 a3 ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_6 = {ba 00 30 10 00 [0-48] 6a 40 52 56 53 89 45 ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_7 = {6a 40 89 45 ?? b8 00 30 10 00 50 56 53 89 45 98 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Afcore_AO_2147641088_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Afcore.AO"
        threat_id = "2147641088"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Afcore"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 02 3d a1 00 00 00 74 1c 8b 0d ?? ?? 00 10 0f b6 11 81 fa eb 00 00 00 74 0b c7 05 ?? ?? ?? 10 ?? ?? ?? ?? cc c7 45 fc 00 00 00 00 eb 09 8b 45 fc 83 c0 01 89 45 fc 83 7d fc 12}  //weight: 1, accuracy: Low
        $x_1_2 = {00 6a 66 75 6e 79 00 00 00 5c 73 79 73 74 65 6d 33 32 5c 73 70 6f 6f 6c 00 73 76 2e 65 78 65 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Afcore_A_2147643818_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Afcore.gen!A"
        threat_id = "2147643818"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Afcore"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AFCORE" ascii //weight: 1
        $x_1_2 = "Octopus has been successfully spawned (PID: %d)" ascii //weight: 1
        $x_1_3 = "shutdown request from service control handler" ascii //weight: 1
        $x_1_4 = "Accepting connection from %a" ascii //weight: 1
        $x_1_5 = "DISKFLOOD" ascii //weight: 1
        $x_1_6 = "Flooding of %s has been completed" ascii //weight: 1
        $x_1_7 = "GetClipboardData" ascii //weight: 1
        $x_1_8 = "PostMessageA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Afcore_H_2147643819_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Afcore.gen!H"
        threat_id = "2147643819"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Afcore"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6d 75 74 65 78 5f 77 69 6e 69 6e 69 74 2e 69 6e 69 00}  //weight: 1, accuracy: High
        $x_1_2 = {83 7d 08 00 75 08 b8 4e 55 4c 3d ab eb 1f}  //weight: 1, accuracy: High
        $x_1_3 = {33 d2 f7 f1 80 c2 61 88 17}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Win32_Afcore_I_2147643939_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Afcore.gen!I"
        threat_id = "2147643939"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Afcore"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "NetDDE Agent %1 Coming Alive" wide //weight: 1
        $x_1_2 = "[ [ verbose = ] DISABLE|ENABLE ]" wide //weight: 1
        $x_10_3 = {6a 40 68 00 30 10 00 ff 73 ?? 6a 00 ff 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Afcore_J_2147644031_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Afcore.gen!J"
        threat_id = "2147644031"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Afcore"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 45 d8 56 c6 45 f4 41 c6 45 e8 46 ff 53}  //weight: 1, accuracy: High
        $x_1_2 = {83 ec 7c 83 7d 0c 01 74 04 32 c0 eb 3f 56 ff 15 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? 8b f0 8d 45 84 a3 ?? ?? ?? ?? 8b 45 08 56 89 45 ?? ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Afcore_K_2147644069_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Afcore.gen!K"
        threat_id = "2147644069"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Afcore"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "A user must possess the Manage auditing and security log user right to access the security log." wide //weight: 1
        $x_1_2 = "3etProcAddr" ascii //weight: 1
        $x_1_3 = {44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74}  //weight: 1, accuracy: High
        $x_1_4 = {83 c4 0c c6 05 ?? ?? ?? ?? 47 c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 73 c6 05 ?? ?? ?? ?? 73 c6 05 ?? ?? ?? ?? 00 8b 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Afcore_L_2147649506_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Afcore.gen!L"
        threat_id = "2147649506"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Afcore"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 45 fc 33 10 8b 0d ?? ?? ?? 00 03 4d fc 89 11 eb b3}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 45 a4 05 20 40 00 8b 4d a4 8b 51 fc 89 95 60 fe ff ff 8b 85 60 fe ff ff 50}  //weight: 1, accuracy: High
        $x_1_3 = {33 c9 81 e9 bc 01 00 00 64 8b 89 d4 01 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

