rule Backdoor_Win32_Joanap_B_2147705780_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Joanap.B!dha"
        threat_id = "2147705780"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Joanap"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {10 20 30 40 50 60 70 80 90 11 12 13 1a ff ee 48}  //weight: 1, accuracy: High
        $x_1_2 = {68 30 75 00 00 8d 44 24 0c 6a 04 50 56 c7 44 24 18 00 10 00 00 e8 ?? ?? 00 00 83 c4 14 83 f8 ff 0f ?? ?? 00 00 00 8d 4c 24 08 51 e8 ?? ?? ff ff 6a 00 68 30 75 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Joanap_B_2147705780_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Joanap.B!dha"
        threat_id = "2147705780"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Joanap"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {10 20 30 40 50 60 70 80 90 11 12 13 1a ff ee 48}  //weight: 1, accuracy: High
        $x_1_2 = {68 30 75 00 00 8d 44 24 0c 6a 04 50 56 c7 44 24 18 00 10 00 00 e8 ?? ?? 00 00 83 c4 14 83 f8 ff 0f ?? ?? 00 00 00 8d 4c 24 08 51 e8 ?? ?? ff ff 6a 00 68 30 75 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Joanap_A_2147705781_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Joanap.A!dha"
        threat_id = "2147705781"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Joanap"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "iamsorry!@1234567" ascii //weight: 10
        $x_1_2 = "01bBHj@23t$46%gh" ascii //weight: 1
        $x_1_3 = "!@#$%^&*" ascii //weight: 1
        $x_1_4 = "%%s\\%%s%%0%dd.%%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Joanap_D_2147705818_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Joanap.D!dha"
        threat_id = "2147705818"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Joanap"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 f7 fd 8a 5c 0c 10 03 f3 8a 92 ?? ?? ?? ?? 03 d6 81 e2 ff 00 00 00 41 8b f2 81 f9 00 01 00 00 8a 44 34 10 88 5c 34 10 88 44 0c 0f 7c ?? 8b 94 24 18 01 00 00 33 f6 33 c0 85 d2 7e}  //weight: 1, accuracy: Low
        $x_1_2 = "IF NOT EXIST %s GOTO " ascii //weight: 1
        $x_1_3 = "RT_RCDATA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Joanap_D_2147705818_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Joanap.D!dha"
        threat_id = "2147705818"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Joanap"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 f7 fd 8a 5c 0c 10 03 f3 8a 92 ?? ?? ?? ?? 03 d6 81 e2 ff 00 00 00 41 8b f2 81 f9 00 01 00 00 8a 44 34 10 88 5c 34 10 88 44 0c 0f 7c ?? 8b 94 24 18 01 00 00 33 f6 33 c0 85 d2 7e}  //weight: 1, accuracy: Low
        $x_1_2 = "IF NOT EXIST %s GOTO " ascii //weight: 1
        $x_1_3 = "RT_RCDATA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Joanap_E_2147705836_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Joanap.E!dha"
        threat_id = "2147705836"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Joanap"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s\\KBD_%s_%02d%02d%02d%02d%02d.CAT" ascii //weight: 1
        $x_1_2 = "~%ld(%ld%%)" ascii //weight: 1
        $x_1_3 = "%s\\oem*.*" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Joanap_E_2147705836_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Joanap.E!dha"
        threat_id = "2147705836"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Joanap"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s\\KBD_%s_%02d%02d%02d%02d%02d.CAT" ascii //weight: 1
        $x_1_2 = "~%ld(%ld%%)" ascii //weight: 1
        $x_1_3 = "%s\\oem*.*" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Joanap_F_2147706500_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Joanap.F!dha"
        threat_id = "2147706500"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Joanap"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 73 5c 25 73 [0-16] 64 76 70 69 2e 64 6e 61 [0-10] 25 73 [0-10] 2e 64 6c 6c}  //weight: 1, accuracy: Low
        $x_1_2 = {64 65 6c 20 2f 61 20 22 25 73 22 [0-16] 69 66 20 65 78 69 73 74 20 22 25 73 22 20 67 6f 74 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Joanap_G_2147706501_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Joanap.G!dha"
        threat_id = "2147706501"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Joanap"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 70 63 73 73 00 [0-10] 25 73 5c 25 73 [0-10] 77 61 75 73 65 72 76 2e 64 6c 6c 00 64 2e 62 61 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Joanap_H_2147707755_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Joanap.H!dha"
        threat_id = "2147707755"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Joanap"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {25 73 62 00 25 73 5c 53 79 73 57 4f 57 36 34 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 56 42 6f 78 48 6f 6f 6b 4e 6f 74 69 66 79 45 76 65 6e 74 00 56 4d 77 61 72 65 55 73 65 72 4d 61 6e 61 67 65 72 45 76 65 6e 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 6d 69 6e 69 2e 64 6c 6c 00 53 65 72 76 69 63 65 4d 61 69 6e 00}  //weight: 1, accuracy: High
        $x_1_4 = {5f 5e 88 41 0e 5d 88 11 33 c2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win32_Joanap_I_2147707756_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Joanap.I!dha"
        threat_id = "2147707756"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Joanap"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {3a 4c 31 0d 0a 73 63 20 73 74 6f 70 20 25 73 0d 0a 73 63 20 64 65 6c 65 74 65 20 25 73 0d 0a 64 65 6c 20 22 25 73 22 0d 0a 64 65 6c 20 22 25 73}  //weight: 2, accuracy: High
        $x_1_2 = {00 5c 53 74 72 69 6e 67 46 69 6c 65 49 6e 66 6f 5c 25 30 38 78 5c 25 73 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 25 73 5c 64 6c 6c 63 61 63 68 65 5c 25 73 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 25 73 5c 25 73 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 44 4c 4c 5f 53 70 69 64 65 72 2e 64 6c 6c 00 53 65 72 76 69 63 65 4d 61 69 6e 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 43 6f 6e 74 65 6e 74 20 6c 65 6e 67 74 68 3a 20 31 30 30 32 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Joanap_K_2147720492_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Joanap.K!dha"
        threat_id = "2147720492"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Joanap"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "myfile" ascii //weight: 10
        $x_10_2 = "%I64d.rst" ascii //weight: 10
        $x_10_3 = "%s?action=What&u=%I64u" wide //weight: 10
        $x_10_4 = "%s?action=CmdRes&u=%I64u&err=exec-%d" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Joanap_L_2147720494_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Joanap.L!dha"
        threat_id = "2147720494"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Joanap"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {01 00 00 2e c6 84 24 ?? ?? 00 00 6d c6 84 24 ?? ?? 00 00 75 c6 84 24 ?? ?? 00 00 69 c6 84 24 ?? ?? 00 00 00 ff 15}  //weight: 10, accuracy: Low
        $x_10_2 = {48 8b d0 41 b9 04 00 00 00 48 03 cd 41 b8 00 10 00 00 ff 15 [0-52] 49 8b 04 24 ff c6 48 83 c7 28 0f b7 48 06 3b f1}  //weight: 10, accuracy: Low
        $x_10_3 = {b8 4d 5a 00 00 49 8b d9 4d 8b e8 4c 8b f2 4c 8b e1 66 39 01 74 ?? b9 c1 00 00 00 ff 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

