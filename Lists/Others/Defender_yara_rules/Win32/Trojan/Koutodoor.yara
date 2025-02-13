rule Trojan_Win32_Koutodoor_B_2147630276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Koutodoor.B.dll!D"
        threat_id = "2147630276"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Koutodoor"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        info = "D: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 64 6c 6c 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72}  //weight: 1, accuracy: High
        $x_1_2 = {68 a1 84 00 00 e8 ?? ?? ?? ?? 83 c4 04}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 00 8d 04 40 8d 04 80 8d 04 80 8d 04 80 8d 04 80 8d 04 80 c1 e0 05 50 68 00 10 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {6a 00 6a 00 6a 00 68 00 00 00 80 6a 00 68 00 00 00 80 68 00 00 cf 00 50 50 6a 00 ff 15 ?? ?? ?? ?? 85 c0 75 ?? c3 8b 4c 24 08 51 50 ff 15 ?? ?? ?? ?? b8 01 00 00 00 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Koutodoor_A_2147630277_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Koutodoor.A"
        threat_id = "2147630277"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Koutodoor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8b c1 99 f7 7d 0c [0-3] 8a 14 ?? [0-8] 32 (c2|d0) 32 (c3|d3) [0-3] 41 3b cb [0-3] 7c}  //weight: 3, accuracy: Low
        $x_1_2 = {53 b8 68 58 4d 56 bb 00 00 00 00 b9 0a 00 00 00 ba 58 56 00 00 ed 81 fb 68 58 4d 56 0f 94 45 e4}  //weight: 1, accuracy: High
        $x_1_3 = "id=%d&mac=%s&type=%d&setupdate=%d%02d%02d&homepage=%s" ascii //weight: 1
        $x_1_4 = "id=%d&updateversion=%d" ascii //weight: 1
        $x_1_5 = "\\\\.\\Global\\rkdoor" ascii //weight: 1
        $x_1_6 = "%s\\%s %s\\%s.dll,%s" ascii //weight: 1
        $x_2_7 = {4d fc 6a 36 68 ?? ?? ?? ?? 8d 55 98 51 52 e8}  //weight: 2, accuracy: Low
        $x_1_8 = {45 fc 6a 17 68 ?? ?? ?? ?? 8d 4d 98 50 51 e8}  //weight: 1, accuracy: Low
        $x_1_9 = {55 fc 6a 0b 68 ?? ?? ?? ?? 8d 4d 98 52 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Koutodoor_B_2147630278_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Koutodoor.B"
        threat_id = "2147630278"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Koutodoor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 7d 0c 8b 45 08 32 0c 02}  //weight: 1, accuracy: High
        $x_1_2 = {81 7d e8 10 84 00 00 74 1c}  //weight: 1, accuracy: High
        $x_1_3 = {3d 20 04 00 00 74 0d ff d7 3d 22 04 00 00 74 04 33 ?? eb 05}  //weight: 1, accuracy: Low
        $x_2_4 = {44 50 00 00 03 00 c7 45 ?? ?? ?? ?? ?? c7 45 ?? 45 50 00 00 c7 45 ?? 3d 50 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Koutodoor_C_2147634342_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Koutodoor.C!dll"
        threat_id = "2147634342"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Koutodoor"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {99 8b ce f7 f9 43 83 fb 04}  //weight: 2, accuracy: High
        $x_2_2 = {8a 45 14 32 c1 47 3b 7d 14}  //weight: 2, accuracy: High
        $x_1_3 = "9348.cn" ascii //weight: 1
        $x_1_4 = "329A624A-1D22-48ae-9576-A02F1EDB1372" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Koutodoor_D_2147636335_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Koutodoor.D"
        threat_id = "2147636335"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Koutodoor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {5c 5c 2e 5c 47 6c 6f 62 61 6c 5c 6b 73 64 72 76 00}  //weight: 3, accuracy: High
        $x_3_2 = "start.php?id=%d" ascii //weight: 3
        $x_1_3 = {73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 25 73 2e 73 79 73 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 72 73 74 72 61 79 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 33 36 30 74 72 61 79 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Koutodoor_D_2147636375_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Koutodoor.D"
        threat_id = "2147636375"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Koutodoor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "329A624A-1D22-48ae-9576-A02F1EDB1372" ascii //weight: 2
        $x_2_2 = "start.php?id=%d" ascii //weight: 2
        $x_1_3 = {73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 25 73 2e 73 79 73 00}  //weight: 1, accuracy: High
        $x_1_4 = {6b 73 77 65 62 73 68 69 65 6c 64 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_5 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 44 61 74 65 54 69 6d 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Koutodoor_E_2147636381_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Koutodoor.E"
        threat_id = "2147636381"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Koutodoor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\\\.\\Global\\ksdrv" ascii //weight: 10
        $x_10_2 = "sion\\Uninstall\\360" ascii //weight: 10
        $x_1_3 = "pp5566.net" ascii //weight: 1
        $x_1_4 = "go2000.cn" ascii //weight: 1
        $x_1_5 = "qq5.com" ascii //weight: 1
        $x_1_6 = "1188.com" ascii //weight: 1
        $x_1_7 = "7f7f.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Koutodoor_E_2147636381_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Koutodoor.E"
        threat_id = "2147636381"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Koutodoor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {75 15 8b 45 fc 40 83 f8 03 89 45 fc 0f 8c ?? ?? ?? ?? 8b 75 f8 eb 05 be 01 00 00 00}  //weight: 3, accuracy: Low
        $x_2_2 = {8a d1 32 d0 88 14 3e 46 3b f1 0f 8c}  //weight: 2, accuracy: High
        $x_2_3 = {25 73 5c 25 73 2e 64 6c 6c [0-5] 25 73 5c 64 72 69 76 65 72 73 5c 25 73 2e 73 79 73}  //weight: 2, accuracy: Low
        $x_1_4 = {72 73 74 72 61 79 2e 65 78 65 [0-5] 33 36 30 74 72 61 79 2e 65 78 65 00}  //weight: 1, accuracy: Low
        $x_1_5 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 44 61 74 65 54 69 6d 65 [0-5] 4c 61 73 74 20 54 69 6d 65}  //weight: 1, accuracy: Low
        $x_1_6 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e [0-5] 53 74 61 72 74 20 50 61 67 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Koutodoor_E_2147636382_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Koutodoor.E"
        threat_id = "2147636382"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Koutodoor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "%s/start.php?id=%d&url=%s" ascii //weight: 2
        $x_1_2 = {6b 73 77 65 62 73 68 69 65 6c 64 2e 64 6c 6c 00 73 61 66 65 6d 6f 6e 2e 64 6c 6c 00 55 72 6c 46 69 6c 74 65 72 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_3 = "www.%s/" ascii //weight: 1
        $x_1_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e [0-5] 53 74 61 72 74 20 50 61 67 65}  //weight: 1, accuracy: Low
        $x_2_5 = {8b 75 08 c6 06 [0-37] c6 46 01 [0-37] c6 46 02 [0-37] c6 46 03}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Koutodoor_F_2147649854_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Koutodoor.F"
        threat_id = "2147649854"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Koutodoor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tt265.net" wide //weight: 1
        $x_1_2 = "my8899.com" wide //weight: 1
        $x_1_3 = "pp1234.net" wide //weight: 1
        $x_1_4 = "the12222.com" wide //weight: 1
        $x_1_5 = "hao455.com" wide //weight: 1
        $x_1_6 = "qu163.net" wide //weight: 1
        $x_10_7 = "currentversion\\runonce" wide //weight: 10
        $x_10_8 = {51 81 f1 dd 06 00 00 66 41 80 f9 23 02 e8 33 ca 3a c9 f6 c5 2b 66 3b c9 80 fd 51 0b c9 59}  //weight: 10, accuracy: High
        $x_10_9 = {66 52 50 66 0d 97 42 66 25 c0 45 85 c6 84 c6 80 fa 51 58 66 5a}  //weight: 10, accuracy: High
        $x_10_10 = {53 66 50 32 c3 80 c4 25 66 3b c2 66 2b c2 81 cb f5 62 00 00 3b df 66 0b c3 f6 c3 01 66 58 5b}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Koutodoor_H_2147718219_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Koutodoor.H!bit"
        threat_id = "2147718219"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Koutodoor"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Software\\Microsoft\\Internet Explorer\\Main" wide //weight: 1
        $x_1_2 = "Start Page" wide //weight: 1
        $x_1_3 = "7f7f.com" ascii //weight: 1
        $x_1_4 = "go2000.cn" ascii //weight: 1
        $x_1_5 = {99 f7 7d 0c 8a 45 ff 32 04 0a}  //weight: 1, accuracy: High
        $x_10_6 = {66 52 50 66 0d 97 42 66 25 c0 45 85 c6 84 c6 80 fa 51 58 66 5a}  //weight: 10, accuracy: High
        $x_10_7 = {53 66 50 32 c3 80 c4 25 66 3b c2 66 2b c2 81 cb f5 62 00 00 3b df 66 0b c3 f6 c3 01 66 58 5b}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

