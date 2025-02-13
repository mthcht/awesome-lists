rule Ransom_Win32_Ergop_A_2147719796_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Ergop.A"
        threat_id = "2147719796"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Ergop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 61 73 6b 6b 69 6c 6c 20 2f 46 20 2f 54 20 2f 50 49 44 [0-8] 61 62 2b [0-8] 77 62 2b [0-8] 25 30 32 58}  //weight: 1, accuracy: Low
        $x_1_2 = {5c 44 65 73 6b 74 6f 70 5c [0-8] 53 69 6e 67 6c 65 20 62 6c 6f 63 6b 20 6d 73 67}  //weight: 1, accuracy: Low
        $x_2_3 = "HOW_OPEN_FILES.hta" ascii //weight: 2
        $x_1_4 = ".crypt" ascii //weight: 1
        $x_1_5 = "\\wall.jpg" ascii //weight: 1
        $x_2_6 = "qwtyufdlkj.tmp" ascii //weight: 2
        $x_2_7 = "rsa_priv_testing.txt" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Ergop_A_2147719796_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Ergop.A"
        threat_id = "2147719796"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Ergop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".707RECOVER-FILE" ascii //weight: 1
        $x_1_2 = "del Default.rdp" ascii //weight: 1
        $x_1_3 = "vssadmin.exe Delete Shadows /All /Quiet" ascii //weight: 1
        $x_1_4 = "for /F \"tokens=*\" %1 in ('wevtutil.exe el') DO wevtutil.exe cl \"%1\"" ascii //weight: 1
        $x_1_5 = "reg delete \"HKEY_CURRENT_USER\\Software\\Microsoft\\Terminal Server Client\\Default\" /va /f" ascii //weight: 1
        $x_1_6 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 4f 00 6e 00 63 00 65 00 [0-8] 43 00 65 00 72 00 74 00 69 00 66 00 69 00 63 00 61 00 74 00 65 00 73 00 43 00 68 00 65 00 63 00 6b 00}  //weight: 1, accuracy: Low
        $x_1_7 = {55 56 57 68 41 00 00 80 ff 15 ?? ?? ?? ?? bf 00 08 00 00 bd ?? ?? ?? ?? 57 55 33 db 53 ff 15}  //weight: 1, accuracy: Low
        $x_2_8 = {50 bd 00 01 00 00 55 68 ?? ?? ?? ?? 56 ff d7 85 c0 0f 84 ?? ?? ff ff 39 6c 24 ?? 0f 85 ?? ?? ff ff 6a 01 53 6a 02 56 ff 15 ?? ?? ?? ?? 53 8d 44 24 ?? 50 68 00 04 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Ergop_B_2147720581_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Ergop.B"
        threat_id = "2147720581"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Ergop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {55 8b ec 83 ec 34 53 56 57 bf 88 60 02 03 57 e8 ca bc ff ff 59 3d b3 01 00 00 76 17 81 7d d8 9b 4b 08 00 74 0e 81 7d d8 04 11 00 00 74 05 e8}  //weight: 100, accuracy: High
        $x_100_2 = {55 8b ec 83 ec 3c 53 56 57 68 28 e8 02 03 e8 6d 03 ff ff 33 db 59 3d b3 01 00 00 0f 86 2b 01 00 00 81 7d d0 9b 4b 08 00 0f 84 1e 01 00 00 81 7d d0 04 11 00 00 0f 84 11 01 00 00 e8 00 ff ff ff}  //weight: 100, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Ransom_Win32_Ergop_B_2147720581_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Ergop.B"
        threat_id = "2147720581"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Ergop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {00 71 66 6a 67 6d 66 67 6d 6b 6a 2e 74 6d 70 00}  //weight: 3, accuracy: High
        $x_1_2 = {00 72 73 61 5f 70 72 69 76 5f 74 65 73 74 69 6e 67 2e 74 78 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 5c 77 61 6c 6c 2e 6a 70 67 00}  //weight: 1, accuracy: High
        $x_1_4 = {73 71 6c 00 6f 75 74 6c 6f 6f 6b 00 73 73 6d 73}  //weight: 1, accuracy: High
        $x_1_5 = "Single block msg" ascii //weight: 1
        $x_2_6 = "\\Users\\a11chemist\\Documents\\" ascii //weight: 2
        $x_2_7 = {5c 61 31 33 6c 6f 63 6b 5f 66 69 6e 61 6c 2e 70 64 62 00}  //weight: 2, accuracy: High
        $x_1_8 = "Delete Shadows /All /Quiet" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Ergop_A_2147722995_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Ergop.A!!Ergop.gen!A"
        threat_id = "2147722995"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Ergop"
        severity = "Critical"
        info = "Ergop: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "del Default.rdp" ascii //weight: 1
        $x_1_2 = "vssadmin.exe Delete Shadows /All /Quiet" ascii //weight: 1
        $x_1_3 = "for /F \"tokens=*\" %1 in ('wevtutil.exe el') DO wevtutil.exe cl \"%1\"" ascii //weight: 1
        $x_1_4 = "reg delete \"HKEY_CURRENT_USER\\Software\\Microsoft\\Terminal Server Client\\Default\" /va /f" ascii //weight: 1
        $x_1_5 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 4f 00 6e 00 63 00 65 00 [0-8] 43 00 65 00 72 00 74 00 69 00 66 00 69 00 63 00 61 00 74 00 65 00 73 00 43 00 68 00 65 00 63 00 6b 00}  //weight: 1, accuracy: Low
        $x_1_6 = {55 56 57 68 41 00 00 80 ff 15 ?? ?? ?? ?? bf 00 08 00 00 bd ?? ?? ?? ?? 57 55 33 db 53 ff 15}  //weight: 1, accuracy: Low
        $x_2_7 = {50 bd 00 01 00 00 55 68 ?? ?? ?? ?? 56 ff d7 85 c0 0f 84 ?? ?? ff ff 39 6c 24 ?? 0f 85 ?? ?? ff ff 6a 01 53 6a 02 56 ff 15 ?? ?? ?? ?? 53 8d 44 24 ?? 50 68 00 04 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Ergop_A_2147722998_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Ergop.gen!A"
        threat_id = "2147722998"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Ergop"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {57 52 0f b7 c1 33 db 50 53 ff 15 ?? ?? ?? ?? 8b f0 56 53 ff 15 ?? ?? ?? ?? 56 53 8b e8 ff 15 ?? ?? ?? ?? 55 8b d8 ff 15 ?? ?? ?? ?? 8d 4b 01 8b f0}  //weight: 2, accuracy: Low
        $x_1_2 = {4b 00 44 00 41 00 54 00 41 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {43 00 4f 00 44 00 41 00 54 00 41 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {45 00 58 00 44 00 41 00 54 00 41 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {73 71 6c 00}  //weight: 1, accuracy: High
        $x_1_6 = {6f 75 74 6c 6f 6f 6b 00}  //weight: 1, accuracy: High
        $x_1_7 = {70 6f 73 74 67 72 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Ergop_C_2147723190_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Ergop.C"
        threat_id = "2147723190"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Ergop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s.[chines34@protonmail.ch].gryphon" ascii //weight: 1
        $x_1_2 = "chines34@protonmail.ch" ascii //weight: 1
        $x_1_3 = "oceannew_vb@protonmail.com" ascii //weight: 1
        $x_2_4 = "SW4gc3ViamVjdCBsaW5lIHdyaXRlICJlbmNyeXB0aW9uIiBhbmQgYXR0" ascii //weight: 2
        $x_2_5 = "DQpZb3VyIHBlcnNvbmFsIGlkZW50aWZpY2F0aW9uIG51bWJlcjoNCg==" ascii //weight: 2
        $x_2_6 = "R1JZUEhPTiBSQU5TT01XQVJF" ascii //weight: 2
        $x_1_7 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCrgpPA8RXwHnCUCVqW" ascii //weight: 1
        $x_1_8 = "!## DECRYPT FILES ##!.txt" ascii //weight: 1
        $x_1_9 = ".gryphon" ascii //weight: 1
        $x_2_10 = "/c vssadmin.exe Delete Shadows /All /Quiet" ascii //weight: 2
        $x_2_11 = "/c bcdedit.exe /set {default} recoveryenabled No" ascii //weight: 2
        $x_2_12 = "/c bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Ergop_D_2147725016_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Ergop.D"
        threat_id = "2147725016"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Ergop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {c7 84 24 84 00 00 00 41 3a 5c 00 33 f6 8d 84 24 ?? ?? 00 00 56 50 e8 ?? ?? ff ff 83 c4 0c 85 db 74 ?? f6 c3 01 74 46 8d 84 24 ?? ?? 00 00 50 ff 15 ?? ?? ?? ?? 83 f8 03 74 ?? 83 f8 02 74 ?? 83 f8 04 75}  //weight: 3, accuracy: Low
        $x_3_2 = {74 12 83 e0 fe 50 8d 84 24 ?? ?? 00 00 50 ff 15 ?? ?? ?? ?? ff 74 24 ?? 8d 84 24 ?? ?? 00 00 ff 74 24 ?? 50 e8 ?? ?? ff ff 85 c0 75 ?? 8d 84 24 ?? ?? 00 00 50 8d 84 24 ?? ?? 00 00 50 ff 15 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? 8d 84 24 ?? ?? 00 00 50 ff d3 6a 01 8d 84 24 ?? ?? 00 00 50 8d 84 24 ?? ?? 00 00 50 ff 15}  //weight: 3, accuracy: Low
        $x_2_3 = {ff 74 24 2c ff 35 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? e8 ?? ?? 00 00 50 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 6a 02 53 53 57 ff 15 ?? ?? ?? ?? 53 8d 44 24 18 bb 00 03 00 00 50 53 68 ?? ?? ?? ?? 57 ff 15}  //weight: 2, accuracy: Low
        $x_2_4 = {ff d5 eb 40 6a 01 6a 00 68 00 20 00 00 53 e8 ?? ?? ff ff 6a 00 8d 44 24 ?? 50 68 00 20 00 00 8d 84 24 ?? ?? 00 00 50 53 ff 15 ?? ?? ?? ?? 8b 4c 24 ?? 33 c0 f7 d9 6a 01 13 c0 f7 d8 50 51 53 e8 ?? ?? ff ff}  //weight: 2, accuracy: Low
        $x_2_5 = {6c 6f 6f 6b [0-8] 73 73 6d 73 [0-8] 70 6f 73 74 67 72 65 [0-8] 31 63 [0-8] 65 78 63 65 6c [0-8] 77 6f 72 64}  //weight: 2, accuracy: Low
        $x_1_6 = {72 73 61 5f 65 6e 63 72 79 70 74 [0-8] 72 73 61 5f 67 65 6e 6b 65 79}  //weight: 1, accuracy: Low
        $x_1_7 = {30 31 30 30 30 31 [0-8] 7b 25 30 38 6c 58 2d 25 30 34 58 2d 25 30 34 58 2d 25 30 32 58 25 30 32 58 2d 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 7d}  //weight: 1, accuracy: Low
        $x_1_8 = "cd %userprofile%\\documents\\" ascii //weight: 1
        $x_2_9 = "attrib Default.rdp -s -h" ascii //weight: 2
        $x_1_10 = "{{IDENTIFIER}}" ascii //weight: 1
        $x_2_11 = "B231B717113902E9F788C7BD0C7ABABAF9B173A7F6B432076B82CBCB7C8149F3CF2F5" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((2 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Ergop_D_2147725017_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Ergop.D!!Ergop.gen!A"
        threat_id = "2147725017"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Ergop"
        severity = "Critical"
        info = "Ergop: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {c7 84 24 84 00 00 00 41 3a 5c 00 33 f6 8d 84 24 ?? ?? 00 00 56 50 e8 ?? ?? ff ff 83 c4 0c 85 db 74 ?? f6 c3 01 74 46 8d 84 24 ?? ?? 00 00 50 ff 15 ?? ?? ?? ?? 83 f8 03 74 ?? 83 f8 02 74 ?? 83 f8 04 75}  //weight: 3, accuracy: Low
        $x_3_2 = {74 12 83 e0 fe 50 8d 84 24 ?? ?? 00 00 50 ff 15 ?? ?? ?? ?? ff 74 24 ?? 8d 84 24 ?? ?? 00 00 ff 74 24 ?? 50 e8 ?? ?? ff ff 85 c0 75 ?? 8d 84 24 ?? ?? 00 00 50 8d 84 24 ?? ?? 00 00 50 ff 15 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? 8d 84 24 ?? ?? 00 00 50 ff d3 6a 01 8d 84 24 ?? ?? 00 00 50 8d 84 24 ?? ?? 00 00 50 ff 15}  //weight: 3, accuracy: Low
        $x_2_3 = {ff 74 24 2c ff 35 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? e8 ?? ?? 00 00 50 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 6a 02 53 53 57 ff 15 ?? ?? ?? ?? 53 8d 44 24 18 bb 00 03 00 00 50 53 68 ?? ?? ?? ?? 57 ff 15}  //weight: 2, accuracy: Low
        $x_2_4 = {ff d5 eb 40 6a 01 6a 00 68 00 20 00 00 53 e8 ?? ?? ff ff 6a 00 8d 44 24 ?? 50 68 00 20 00 00 8d 84 24 ?? ?? 00 00 50 53 ff 15 ?? ?? ?? ?? 8b 4c 24 ?? 33 c0 f7 d9 6a 01 13 c0 f7 d8 50 51 53 e8 ?? ?? ff ff}  //weight: 2, accuracy: Low
        $x_2_5 = {6c 6f 6f 6b [0-8] 73 73 6d 73 [0-8] 70 6f 73 74 67 72 65 [0-8] 31 63 [0-8] 65 78 63 65 6c [0-8] 77 6f 72 64}  //weight: 2, accuracy: Low
        $x_1_6 = {72 73 61 5f 65 6e 63 72 79 70 74 [0-8] 72 73 61 5f 67 65 6e 6b 65 79}  //weight: 1, accuracy: Low
        $x_1_7 = {30 31 30 30 30 31 [0-8] 7b 25 30 38 6c 58 2d 25 30 34 58 2d 25 30 34 58 2d 25 30 32 58 25 30 32 58 2d 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 7d}  //weight: 1, accuracy: Low
        $x_1_8 = "cd %userprofile%\\documents\\" ascii //weight: 1
        $x_2_9 = "attrib Default.rdp -s -h" ascii //weight: 2
        $x_1_10 = "{{IDENTIFIER}}" ascii //weight: 1
        $x_2_11 = "B231B717113902E9F788C7BD0C7ABABAF9B173A7F6B432076B82CBCB7C8149F3CF2F5" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((2 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Ergop_E_2147725028_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Ergop.E"
        threat_id = "2147725028"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Ergop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 2e 2e 64 6f 63 00 52 65 61 64 5f 5f 5f 4d 45 2e 68 74 6d 6c 00 2e 2e 64 6f 63}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

