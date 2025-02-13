rule Backdoor_Win32_Talsab_A_2147627796_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Talsab.A"
        threat_id = "2147627796"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Talsab"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {b8 68 58 4d 56 bb 00 00 00 00 b9 0a 00 00 00 ba 58 56 00 00 ed 81 fb 68 58 4d 56 0f 94 45 ff}  //weight: 2, accuracy: High
        $x_2_2 = {83 c0 eb 83 f8 05 0f 87 ?? ?? 00 00 ff 24 85 ?? ?? 45 00}  //weight: 2, accuracy: Low
        $x_2_3 = {8a c3 83 f8 14 0f 87 ?? ?? 00 00 ff 24 85 ?? ?? 45 00}  //weight: 2, accuracy: Low
        $x_2_4 = {b2 03 b0 02 e8 ?? ?? ff ff 8d 4d e0 b2 04 b0 01 e8 ?? ?? ff ff 8d 4d dc b2 02 b0 02}  //weight: 2, accuracy: Low
        $x_1_5 = {43 6f 6e 66 69 67 50 61 74 68 00 [0-10] 44 65 76 69 63 65 50 61 74 68 00 [0-10] 4d 65 64 69 61 50 61 74 68 00 [0-10] 57 61 6c 6c 50 61 70 65 72 44 69 72 00}  //weight: 1, accuracy: Low
        $x_1_6 = {41 70 70 44 61 74 61 00 [0-10] 46 6f 6e 74 73 00 [0-10] 53 65 6e 64 54 6f 00 [0-10] 52 65 63 65 6e 74 00 [0-10] 46 61 76 6f 72 69 74 65 73 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Talsab_B_2147627820_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Talsab.B"
        threat_id = "2147627820"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Talsab"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {b8 68 58 4d 56 bb 00 00 00 00 b9 0a 00 00 00 ba 58 56 00 00 ed 81 fb 68 58 4d 56 0f 94 45 ff}  //weight: 2, accuracy: High
        $x_2_2 = {84 c0 c7 45 fc ff ff ff ff 8b 45 0c 50 53 6a 00 e8 ?? ?? ?? ff 8b f0 6a 00 68 80 00 00 00 6a 02 6a 00 6a 02 68 00 00 00 40 8d 55 f4 b0 05 e8}  //weight: 2, accuracy: Low
        $x_2_3 = {ba 44 00 00 00 e8 ?? ?? ?? ff c7 45 b4 44 00 00 00 c7 45 e0 01 00 00 00 66 89 5d e4 8d 45 a4 50 8d 45 b4 50 6a 00 6a 00 68 10 01 00 00}  //weight: 2, accuracy: Low
        $x_2_4 = {ba 01 00 00 80 8b 45 f8 e8 ?? ?? ?? ff b1 01 ba ?? ?? ?? 00 8b 45 f8 e8 ?? ?? ?? ff 80 eb 05 75 10 8b 4d fc ba ?? ?? ?? 00 8b 45 f8 e8}  //weight: 2, accuracy: Low
        $x_2_5 = {5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 20 46 6f 6c 64 65 72 73 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 41 70 70 44 61 74 61 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Win32_Talsab_B_2147637347_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Talsab.B"
        threat_id = "2147637347"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Talsab"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {b9 3f 00 00 00 8b c3 e8 ?? ?? ?? ?? 85 c0 0f 85 ?? ?? ?? ?? 83 bd ?? ?? ?? ?? 02 0f 85 ?? ?? ?? ?? 8b b5 ?? ?? ?? ?? 8b c6 83 e0 10 83 f8 10 0f 84 ?? ?? ?? ?? 8d 45 ?? e8 ?? ?? ?? ?? 8b c6 83 e0 01 48 75 0d}  //weight: 2, accuracy: Low
        $x_2_2 = {b8 68 58 4d 56 bb 00 00 00 00 b9 0a 00 00 00 ba 58 56 00 00 ed 81 fb 68 58 4d 56 0f 94 45 ff}  //weight: 2, accuracy: High
        $x_1_3 = "WindowsLive:name=*" ascii //weight: 1
        $x_1_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 20 46 6f 6c 64 65 72 73 00 [0-16] 41 70 70 44 61 74 61 00 [0-16] 4c 6f 63 61 6c 20 41 70 70 44 61 74 61 00}  //weight: 1, accuracy: Low
        $x_1_5 = {7c 44 49 52 23 30 23 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Talsab_C_2147643217_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Talsab.C"
        threat_id = "2147643217"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Talsab"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {b8 68 58 4d 56 bb 00 00 00 00 b9 0a 00 00 00 ba 58 56 00 00 ed 81 fb 68 58 4d 56 0f 94 45 ff}  //weight: 2, accuracy: High
        $x_1_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 20 46 6f 6c 64 65 72 73 00 [0-16] 41 70 70 44 61 74 61 00 [0-16] 4c 6f 63 61 6c 20 41 70 70 44 61 74 61 00}  //weight: 1, accuracy: Low
        $x_1_3 = {26 69 63 65 72 69 6b 3d 00}  //weight: 1, accuracy: High
        $x_2_4 = {74 32 6a 00 68 a1 0f 00 00 8d 83 ?? ?? ?? ?? 50 8b 43 04 50 e8 ?? ?? ?? ?? 8d 83 ?? ?? ?? ?? 33 c9 ba a1 0f 00 00 e8 ?? ?? ?? ?? 83 bb ?? ?? ?? ?? 00 75 ad}  //weight: 2, accuracy: Low
        $x_1_5 = {77 00 00 00 ff ff ff ff 01 00 00 00 61 00 00 00 ff ff ff ff 01 00 00 00 72 00 00 00 ff ff ff ff 01 00 00 00 64 00 00 00 ff ff ff ff 01 00 00 00 6f 00 00 00 ff ff ff ff 01 00 00 00 6e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Talsab_E_2147665965_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Talsab.E"
        threat_id = "2147665965"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Talsab"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6e 74 6c 64 72 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 32 30 35 2e 32 35 31 2e 31 34 30 2e 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 48 6f 73 74 3a 20 77 77 77 2e 00}  //weight: 1, accuracy: High
        $x_1_4 = "/1stemail.php HTTP/1.1" ascii //weight: 1
        $x_1_5 = {5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 00}  //weight: 1, accuracy: High
        $x_1_6 = "del sys.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Talsab_F_2147665966_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Talsab.F"
        threat_id = "2147665966"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Talsab"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b8 68 58 4d 56 bb 00 00 00 00 b9 0a 00 00 00 ba 58 56 00 00 ed}  //weight: 1, accuracy: High
        $x_1_2 = "local.foo.com" ascii //weight: 1
        $x_1_3 = ".info/1stemail.php" ascii //weight: 1
        $x_1_4 = {00 6e 74 6c 64 72 2e 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Talsab_G_2147665967_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Talsab.G"
        threat_id = "2147665967"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Talsab"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 66 64 77 61 71 65 36 32 33 00}  //weight: 1, accuracy: High
        $x_1_2 = {b8 68 58 4d 56 bb 00 00 00 00 b9 0a 00 00 00 ba 58 56 00 00 ed}  //weight: 1, accuracy: High
        $x_1_3 = {00 6e 74 6c 64 72 2e 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Talsab_H_2147665968_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Talsab.H"
        threat_id = "2147665968"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Talsab"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b8 68 58 4d 56 bb 00 00 00 00 b9 0a 00 00 00 ba 58 56 00 00 ed}  //weight: 1, accuracy: High
        $x_1_2 = {6e 74 6c 64 72 2e 64 6c 6c 00 00 00 79 6f 6b 6c 61 6d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Talsab_D_2147665969_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Talsab.D"
        threat_id = "2147665969"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Talsab"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "205.251.140.1" ascii //weight: 1
        $x_1_2 = {64 65 73 74 69 6e 6f 3d [0-47] 75 73 65 72 3d [0-47] 26 69 63 65 72 69 6b 3d}  //weight: 1, accuracy: Low
        $x_1_3 = "fdwaqe623" ascii //weight: 1
        $x_1_4 = {b8 68 58 4d 56 bb 00 00 00 00 b9 0a 00 00 00 ba ?? ?? ?? ?? ed 81 fb 68 58 4d 56 0f 94 45 ff 5b 59 5a 33 c0 5a 59 59 64 89 10 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

