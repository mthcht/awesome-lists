rule Trojan_Win32_Swrort_A_2147630763_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Swrort.A"
        threat_id = "2147630763"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Swrort"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5d 68 33 32 00 00 68 77 73 32 5f 54 68 4c 77 26 07 ff d5 b8 90 01 00 00 29 c4 54 50 68 29 80 6b 00 ff d5}  //weight: 1, accuracy: High
        $x_1_2 = {e3 3c 49 8b 34 8b 01 d6 31 ff 31 c0 ac c1 cf 0d 01 c7 38 e0 75 f4 03 7d f8 3b 7d 24 75 e2}  //weight: 1, accuracy: High
        $x_1_3 = {89 e6 6a 10 56 57 68 ?? ?? ?? ?? ff d5 05 00 68 02 00}  //weight: 1, accuracy: Low
        $x_1_4 = {68 58 a4 53 e5 [0-2] [0-2] ff d5}  //weight: 1, accuracy: Low
        $x_1_5 = {68 a6 95 bd 9d [0-2] [0-2] ff d5}  //weight: 1, accuracy: Low
        $n_10_6 = {68 ad 13 6c dd 68 02 00 00 50 89 e6 6a 10 56 57 68 99 a5 74 61 ff d5}  //weight: -10, accuracy: High
        $n_100_7 = "y:\\x64\\Release\\apihook64.pdb" ascii //weight: -100
        $n_100_8 = "y:\\Release\\apihook.pdb" ascii //weight: -100
        $n_100_9 = "Malwarebytes Anti-Exploit - Exploit Test" ascii //weight: -100
        $n_100_10 = {20 00 4d 00 61 00 6c 00 77 00 61 00 72 00 65 00 62 00 79 00 74 00 65 00 73 00 20 00 41 00 6e 00 74 00 69 00 2d 00 45 00 78 00 70 00 6c 00 6f 00 69 00 74 00 20 00 69 00 73 00 20 00 [0-32] 77 00 6f 00 72 00 6b 00 69 00 6e 00 67 00 20 00 63 00 6f 00 72 00 72 00 65 00 63 00 74 00 6c 00 79 00}  //weight: -100, accuracy: Low
        $n_100_11 = "D:\\jenkins\\workspace\\Minerva_GenerateInstallers-BIOCOMPGLAUKA\\EndPoint\\BIN\\Release\\rmmpa.pdb" ascii //weight: -100
        $n_100_12 = "d:\\TFS\\Minerva\\DEV-branch-3.2.119-SANTANDER\\EndPoint\\BIN\\Release\\rmmpa.pdb" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (2 of ($x*))
}

rule Trojan_Win32_Swrort_C_2147656416_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Swrort.C"
        threat_id = "2147656416"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Swrort"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5e 56 31 1e ad 01 c3 85 c0 75 f7}  //weight: 1, accuracy: High
        $x_1_2 = {e8 ff ff ff ff c0 5e 81 76 0e ?? ?? ?? ?? 83 ee fc e2 f4}  //weight: 1, accuracy: Low
        $n_100_3 = "C:\\ProgramData\\Symantec\\Symantec Endpoint Protection\\12.1.7004.6500.105\\Data" wide //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_Swrort_E_2147711073_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Swrort.E!bit"
        threat_id = "2147711073"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Swrort"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f3 a5 6a 40 68 00 10 00 00 68 ?? 01 00 00 [0-16] ff 15 ?? ?? 40 00 8b f8 [0-16] ff d0}  //weight: 1, accuracy: Low
        $x_1_2 = {fc e8 82 00 00 00 60 89 e5 31 c0 64 8b 50 30 8b 52 0c 8b 52 14 8b 72 28 0f b7 4a 26 31 ff ac 3c 61 7c 02 2c 20 c1 cf 0d 01 c7 e2 f2 52 57 8b 52 10 8b 4a 3c 8b 4c 11 78 e3 48 01 d1 51 8b 59 20 01 d3 8b 49 18 e3 3a 49 8b 34 8b 01 d6 31 ff ac c1 cf 0d 01 c7 38 e0 75 f6 03 7d f8 3b 7d 24 75 e4 58 8b 58 24 01 d3 66 8b 0c 4b 8b 58 1c 01 d3 8b 04 8b 01 d0 89 44 24 24 5b 5b 61 59 5a 51 ff e0 5f 5f 5a 8b 12 eb 8d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Swrort_A_2147721311_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Swrort.A!!Swrort.gen!A"
        threat_id = "2147721311"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Swrort"
        severity = "Critical"
        info = "Swrort: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 29 80 6b 00}  //weight: 1, accuracy: High
        $x_1_2 = {68 ea 0f df e0}  //weight: 1, accuracy: High
        $x_1_3 = {68 c2 db 37 67}  //weight: 1, accuracy: High
        $x_1_4 = {68 b7 e9 38 ff}  //weight: 1, accuracy: High
        $x_1_5 = {68 74 ec 3b e1}  //weight: 1, accuracy: High
        $x_1_6 = "hunMa" ascii //weight: 1
        $x_1_7 = {68 63 6d 64 00}  //weight: 1, accuracy: High
        $x_1_8 = {68 79 cc 3f 86}  //weight: 1, accuracy: High
        $x_2_9 = {5d 68 33 32 00 00 68 77 73 32 5f 54 68 ?? ?? ?? ?? ff d5}  //weight: 2, accuracy: Low
        $x_4_10 = {3b 7d 24 75 e4 58 8b 58 24 01 d3 66 8b 0c 4b 8b 58 1c 01 d3 8b 04 8b 01 d0 89 44 24 24 5b 5b 61 59 5a 51 ff e0}  //weight: 4, accuracy: High
        $x_2_11 = {ff d5 3c 06 7c 0a 80 fb e0 75 05 bb ?? ?? ?? ?? 6a 00 53 ff d5}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Swrort_AB_2147826901_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Swrort.AB!MTB"
        threat_id = "2147826901"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Swrort"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {6a 00 6a 00 6a 44 6a 01 6a 00 6a 00 68 1c 42 00 10 6a 00 ff 15}  //weight: 5, accuracy: High
        $x_5_2 = {6a 40 68 00 10 00 00 68 00 10 00 00 6a 00 8b 4d e8 51 ff 15}  //weight: 5, accuracy: High
        $x_5_3 = {6a 00 68 00 10 00 00 68 00 30 00 10 8b 55 f8 52 8b 45 e8 50 ff 15}  //weight: 5, accuracy: High
        $x_1_4 = "D$$[[aYZQ" ascii //weight: 1
        $x_1_5 = "1<1F1P1Z1b1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

