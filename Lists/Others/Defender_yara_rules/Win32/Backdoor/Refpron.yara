rule Backdoor_Win32_Refpron_A_2147608588_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Refpron.A"
        threat_id = "2147608588"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Refpron"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {32 cb 88 4c 10 ff 0f b7 45 f2 8b 55 fc 0f b6 44 02 ff 66 03 45 f0 66 69 c0 6d ce 66 05 bf 58 66 89 45 f0 66 ff 45 f2 66 ff 4d ee}  //weight: 5, accuracy: High
        $x_2_2 = "WriteProcessMemory" ascii //weight: 2
        $x_2_3 = "CreateRemoteThread" ascii //weight: 2
        $x_1_4 = "C:\\WINDOWS\\SYSTEM32\\drmgs.sys" ascii //weight: 1
        $x_1_5 = "p_ver:200" ascii //weight: 1
        $x_1_6 = ".sys not found!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Refpron_B_2147610036_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Refpron.B"
        threat_id = "2147610036"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Refpron"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {32 cb 88 4c 10 ff 0f b7 45 f2 8b 55 fc 0f b6 44 02 ff 66 03 45 f0 66 69 c0 6d ce 66 05 bf 58 66 89 45 f0 66 ff 45 f2 66 ff 4d ee}  //weight: 10, accuracy: High
        $x_10_2 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_1_3 = "e_r_r_o_r" ascii //weight: 1
        $x_1_4 = "Open   File   Error" ascii //weight: 1
        $x_1_5 = "TMy_M_i_niT_C_PC_lient" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Refpron_C_2147610105_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Refpron.C"
        threat_id = "2147610105"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Refpron"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_2_2 = {8a 54 3a ff 0f b7 ce c1 e9 08 32 d1 88 54 38 ff 8b 04 24 0f b6 44 38 ff 66 03 f0 66 69 c6 6d ce 66 05 bf 58 8b f0 43 66 ff 4c 24 04 75}  //weight: 2, accuracy: High
        $x_2_3 = {8a 54 2a ff 0f b7 cf c1 e9 08 32 d1 88 54 28 ff 8b 06 0f b6 44 28 ff 66 03 f8 66 69 c7 6d ce 66 05 bf 58 8b f8 43 66 ff 0c 24 75}  //weight: 2, accuracy: High
        $x_1_4 = "e_rro_r" ascii //weight: 1
        $x_1_5 = "e_rr_o_r" ascii //weight: 1
        $x_1_6 = "Open   File   Error!!!" ascii //weight: 1
        $x_1_7 = "TMy_M_i_niT_C_PC_lient" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Refpron_D_2147610281_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Refpron.D"
        threat_id = "2147610281"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Refpron"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c7 40 7c 88 13 00 00 8b 45 ?? c7 40 78 35 00 00 00 8b 45 ?? 83 c0 74 8b 55 f8 e8}  //weight: 2, accuracy: Low
        $x_7_2 = {56 62 42 45 36 6c 35 4f 55 6a 55 4c 45 33 52 4b 43 71 45 55 50 70 67 6f 64 35 48 79 39 63 36 71 68 4e 35 6e 58 75 34 66 43 52 38 65 38 72 49 72 4f 6e 49 6a 62 5a 34 58 7a 33 5a 36 4a 66 71 52 79 64 6e 42 6d 32 43 48 2b 44 62 57 7a 36 48 00 ff ff ff ff 12 00 00 00 57 61 72 6e 4f 6e 5a 6f 6e 65 43 72 6f 73 73 69 6e 67 00 00 ff ff ff ff 12 00 00 00 57 61 72 6e 4f 6e 50 6f 73 74 52 65 64 69 72 65 63 74 00 00}  //weight: 7, accuracy: High
        $x_2_3 = "VbBE6l5OUjULE3RKCqEUPpgodBmHS5mNuXsK9dddh8Q8L1guit2tunL" ascii //weight: 2
        $x_1_4 = {00 44 69 73 61 62 6c 65 20 53 63 72 69 70 74 20 44 65 62 75 67 67 65 72 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 6e 65 74 73 74 61 74 20 2d 61 20 2d 6e 20 2d 70 20 74 63 70 20 7c 20 66 69 6e 64 73 74 72 20 4c 49 53 54 45 4e 49 4e 47 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 45 52 52 4f 61 52 3a 6d}  //weight: 1, accuracy: High
        $x_1_7 = {52 3a 46 65 6e 62 58 69 41 64 73 5f 50 61 63 6b 61 5f 67 65 3a 00}  //weight: 1, accuracy: High
        $x_1_8 = {4f 52 3a 52 5f 55 5f 4e 5f 41 5f 44 5f 53 3a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_7_*) and 3 of ($x_1_*))) or
            ((1 of ($x_7_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_7_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Refpron_E_2147610426_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Refpron.E"
        threat_id = "2147610426"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Refpron"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {56 62 42 45 36 6c 35 4f 55 6a 55 4c 45 33 52 4b 43 71 45 55 50 70 67 6f 64 35 48 79 39 63 36 71 68 4e 35 6e 58 75 34 66 43 52 38 65 38 72 49 72 4f 6e 49 6a 62 5a 34 58 7a 33 5a 36 4a 66 71 52 79 64 6e 42 6d 32 43 48 2b 44 62 57 7a 36 48 00 ff ff ff ff 12 00 00 00 57 61 72 6e 4f 6e 5a 6f 6e 65 43 72 6f 73 73 69 6e 67 00 00 ff ff ff ff 12 00 00 00 57 61 72 6e 4f 6e 50 6f 73 74 52 65 64 69 72 65 63 74 00 00}  //weight: 10, accuracy: High
        $x_10_2 = {6e 65 74 73 74 61 74 20 2d 61 20 2d 6e 20 2d 70 20 74 63 70 20 7c 20 66 69 6e 64 73 74 72 20 4c 49 53 54 45 4e 49 4e 47 00}  //weight: 10, accuracy: High
        $x_10_3 = {57 61 72 6e 6f 6e 42 61 64 43 65 72 74 52 65 63 76 69 6e 67 00}  //weight: 10, accuracy: High
        $x_10_4 = "Sexme:" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Refpron_I_2147616542_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Refpron.I"
        threat_id = "2147616542"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Refpron"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 05 bf 58 0b 00 [0-6] 66 69 ?? 6d ce}  //weight: 1, accuracy: Low
        $x_2_2 = {68 00 10 00 00 [0-4] 6a 00 6a 06 a1 ?? ?? 43 00 50 e8 04 00 00 90 03 00}  //weight: 2, accuracy: Low
        $x_1_3 = {63 00 00 00 02 00 00 00 5c 00 00 00 02 00 00 00 50 00 00 00 02 00 00 00 68 00 00 00 02 00 00 00 79 00 00 00 02 00 00 00 73 00 00 00 02 00 00 00 61 00 00 00 02 00 00 00 6c 00 00 00 02 00 00 00 4d 00 00 00 02 00 00 00 6d 00 00 00 02 00 00 00 6f 00 00 00 02 00 00 00 72 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 53 65 74 20 04 00 46 69 6c 65 20 04 00 54 69 6d 65 20 04 00 53 75 63 63 65 73 73 66 75 6c 6c 79 21 21 21 00}  //weight: 1, accuracy: Low
        $x_1_5 = {61 64 6c 69 6e 6b 3d 00 ff ff ff ff 06 00 00 00 63 6c 69 63 6b 3d 00 00 ff ff ff ff 07 00 00 00 69 73 48 69 74 73 3d 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 6e 72 6e 64 66 6f 72 63 74 72 32 3d 00}  //weight: 1, accuracy: High
        $x_1_7 = "&border_color=FFFFFF&newwin=&zs=&width=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Refpron_K_2147618757_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Refpron.K"
        threat_id = "2147618757"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Refpron"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 54 2a ff 0f b7 cf c1 e9 08 32 d1 88 54 28 ff 8b 06 0f b6 44 28 ff 66 03 f8 66 69 c7 6d ce 66 05 bf 58 8b f8 43 66 ff 0c 24 75}  //weight: 2, accuracy: High
        $x_2_2 = {00 53 65 74 20 04 00 46 69 6c 65 20 04 00 54 69 6d 65 20 04 00 53 75 63 63 65 73 73 66 75 6c 6c 79 21 21 21 00}  //weight: 2, accuracy: Low
        $x_1_3 = {03 00 68 00 10 00 00 [0-4] 6a 00 6a 06 a1}  //weight: 1, accuracy: Low
        $x_1_4 = {63 00 00 00 02 00 00 00 5c 00 00 00 02 00 00 00 50 00 00 00 02 00 00 00 68 00 00 00 02 00 00 00 79 00 00 00 02 00 00 00 73 00 00 00 02 00 00 00 61 00 00 00 02 00 00 00 6c 00 00 00 02 00 00 00 4d 00 00 00 02 00 00 00 6d 00 00 00 02 00 00 00 6f 00 00 00 02 00 00 00 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Refpron_M_2147622485_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Refpron.M"
        threat_id = "2147622485"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Refpron"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {65 5f 72 5f 72 5f 6f 5f 72 5f 00}  //weight: 1, accuracy: High
        $x_1_2 = {63 6f 6d 73 61 33 32 2e 73 79 73 00}  //weight: 1, accuracy: High
        $x_1_3 = {66 69 c0 6d ce 66 05 bf 58}  //weight: 1, accuracy: High
        $x_1_4 = {69 45 e8 6d ce 00 00 89 45 e4 ff 45 ec 66 8b 45 e4 66 05 bf 58}  //weight: 1, accuracy: High
        $x_1_5 = "bfkq.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Win32_Refpron_C_2147623163_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Refpron.gen!C"
        threat_id = "2147623163"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Refpron"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {63 6f 6d 73 61 33 32 2e 73 79 73 00}  //weight: 10, accuracy: High
        $x_2_2 = "WarnOnHTTPSToHTTPRedirect" ascii //weight: 2
        $x_2_3 = "URLDownloadToFileA" ascii //weight: 2
        $x_2_4 = "/install /silent" ascii //weight: 2
        $x_1_5 = "174.133.72.250" ascii //weight: 1
        $x_1_6 = "174.133.126.2" ascii //weight: 1
        $x_1_7 = "74.55.37.210" ascii //weight: 1
        $x_1_8 = "74.54.201.210" ascii //weight: 1
        $x_1_9 = "jsactivity.com" ascii //weight: 1
        $x_1_10 = "bfkq.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Refpron_P_2147627232_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Refpron.P"
        threat_id = "2147627232"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Refpron"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d ce 00 00 [0-32] 66 81 45 ?? bf 58}  //weight: 1, accuracy: Low
        $x_1_2 = "bfkq.com|" ascii //weight: 1
        $x_1_3 = "|jsactivity.com" ascii //weight: 1
        $x_1_4 = {4e 65 65 64 4b 69 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_5 = {6e 72 6e 64 66 6f 72 63 74 72 31 00}  //weight: 1, accuracy: High
        $x_1_6 = {5c 53 79 73 74 65 6d 45 78 63 6c 61 6d 61 74 69 6f 6e 5c 2e 43 75 72 72 65 6e 74 00}  //weight: 1, accuracy: High
        $x_1_7 = {64 69 73 63 6f 76 65 72 2e 65 78 65 3d 00}  //weight: 1, accuracy: High
        $x_1_8 = {6d 00 00 00 ff ff ff ff 01 00 00 00 73 00 00 00 ff ff ff ff 01 00 00 00 2e 00 00 00 ff ff ff ff 01 00 00 00 62 00 00 00 ff ff ff ff 01 00 00 00 69 00 00 00 ff ff ff ff 01 00 00 00 6e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Backdoor_Win32_Refpron_Q_2147629531_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Refpron.Q"
        threat_id = "2147629531"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Refpron"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "software\\microsoft\\wbem" ascii //weight: 1
        $x_1_2 = {65 5f 72 5f 72 5f 6f 5f 72 5f 00}  //weight: 1, accuracy: High
        $x_1_3 = "|jsactivity.com" ascii //weight: 1
        $x_1_4 = "bfkq.com|" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Refpron_R_2147630761_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Refpron.R"
        threat_id = "2147630761"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Refpron"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 30 00 00 00 6a 00 6a 00 49 75 f9 53 33 c0 55 68 ?? 75 01 00 64 ff 30 64 89 20 68 ?? ?? ?? 40 6a 00 8d 55 fc b8 ?? 75 01 00 e8 ?? d7 ff ff 8b 45 fc e8 ?? c7 ff ff 8b 15 40 92 01 00 89 02 68 ?? ?? ?? 40 6a 00 8d 55 fc b8 ?? 75 01 00 e8 ?? d7 ff ff 8b 45 fc e8 ?? c7 ff ff 8b 15 5c 91 01 00 89 02 68 ?? ?? ?? 40 6a 00}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b7 45 f0 c1 e8 08 89 45 e4 83 6d ec ?? 8b 45 f4 e8 ?? e7 ff ff 0f b7 55 f2 8a 4d e8 32 4d e4 88 4c 10 ff}  //weight: 1, accuracy: Low
        $x_1_3 = "ServiceMain" ascii //weight: 1
        $x_1_4 = "Portions Copyright (c) 1983,99 Borland" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

