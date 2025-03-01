rule Trojan_Win32_Killfiles_A_2147600531_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killfiles.gen!A"
        threat_id = "2147600531"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killfiles"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_vbaPrintFile" ascii //weight: 1
        $x_1_2 = "@*\\AC:\\Documents and Settings" wide //weight: 1
        $x_10_3 = "@del C:\\windows\\*.exe" wide //weight: 10
        $x_10_4 = "@del C:\\windows\\*.com" wide //weight: 10
        $x_10_5 = "@del C:\\windows\\system32\\*.scr" wide //weight: 10
        $x_10_6 = "@del C:\\windows\\SYSTEM32\\*.exe" wide //weight: 10
        $x_10_7 = "@del C:\\windows\\SYSTEM32\\*.drv" wide //weight: 10
        $x_10_8 = "@del C:\\windows\\system32\\*.dll" wide //weight: 10
        $x_10_9 = "@del C:\\windows\\SYSTEM32\\*.sys" wide //weight: 10
        $x_10_10 = "@del C:\\windows\\SYSTEM32\\*.com" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Killfiles_EG_2147605033_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killfiles.EG"
        threat_id = "2147605033"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killfiles"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "66"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = "title" ascii //weight: 20
        $x_20_2 = "Label c: Lin" ascii //weight: 20
        $x_1_3 = {64 65 6c 20 [0-8] 2f 73 [0-8] 20 64 3a}  //weight: 1, accuracy: Low
        $x_1_4 = {64 65 6c 20 [0-8] 2f 73 [0-8] 20 45 3a}  //weight: 1, accuracy: Low
        $x_1_5 = {64 65 6c 20 [0-8] 2f 73 [0-8] 20 46 3a}  //weight: 1, accuracy: Low
        $x_1_6 = {64 65 6c 20 [0-8] 2f 73 [0-8] 20 47 3a}  //weight: 1, accuracy: Low
        $x_1_7 = {64 65 6c 20 [0-8] 2f 73 [0-8] 20 63 3a 2a 2e 78 6c 73}  //weight: 1, accuracy: Low
        $x_1_8 = {64 65 6c 20 [0-8] 2f 73 [0-8] 20 63 3a 2a 2e 72 61 72}  //weight: 1, accuracy: Low
        $x_1_9 = {64 65 6c 20 [0-8] 2f 73 [0-8] 20 63 3a 2a 2e 7a 69 70}  //weight: 1, accuracy: Low
        $x_1_10 = {64 65 6c 20 [0-8] 2f 73 [0-8] 20 63 3a 2a 2e 70 70 74}  //weight: 1, accuracy: Low
        $x_1_11 = {64 65 6c 20 [0-8] 2f 73 [0-8] 20 63 3a 2a 2e 6d 70 33}  //weight: 1, accuracy: Low
        $x_1_12 = {64 65 6c 20 [0-8] 2f 73 [0-8] 20 63 3a 2a 2e 61 76 69}  //weight: 1, accuracy: Low
        $x_1_13 = {64 65 6c 20 [0-8] 2f 73 [0-8] 20 63 3a 2a 2e 69 73 6f}  //weight: 1, accuracy: Low
        $x_1_14 = {64 65 6c 20 [0-8] 2f 73 [0-8] 20 63 3a 2a 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_15 = {64 65 6c 20 [0-8] 2f 73 [0-8] 20 63 3a 2a 2e 73 79 73}  //weight: 1, accuracy: Low
        $x_1_16 = {64 65 6c 20 [0-8] 2f 73 [0-8] 20 63 3a 2a 2e 69 6e 69}  //weight: 1, accuracy: Low
        $x_1_17 = {64 65 6c 20 [0-8] 2f 73 [0-8] 20 63 3a 2a 2e 47 48 4f}  //weight: 1, accuracy: Low
        $x_1_18 = {64 65 6c 20 [0-8] 2f 73 [0-8] 20 63 3a 2a 2e 62 61 74}  //weight: 1, accuracy: Low
        $x_1_19 = {64 65 6c 20 [0-8] 2f 73 [0-8] 20 63 3a 2a 2e 74 78 74}  //weight: 1, accuracy: Low
        $x_20_20 = {55 89 e5 83 ec 08 83 e4 f0 b8 00 00 00 00 83 c0 0f 83 c0 0f c1 e8 04 c1 e0 04 89 45 fc 8b 45 fc e8 ?? ?? 00 00 e8 ?? ?? 00 00 c7 04 24 ?? ?? 40 00 e8 ?? ?? 00 00 c7 04 24 ?? ?? 40 00 e8 ?? ?? 00 00 c7 04 24 ?? ?? 40 00 e8 ?? ?? 00 00 c7 04 24 ?? ?? 40 00}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_20_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Killfiles_RZ_2147608090_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killfiles.RZ"
        threat_id = "2147608090"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killfiles"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "\\windows\\system32\\removegb.sys" ascii //weight: 4
        $x_4_2 = {44 52 56 20 52 20 47 42 00 00 00 00 72 65 6d 6f 76 65 67 62}  //weight: 4, accuracy: High
        $x_3_3 = "MicrosoftNET" ascii //weight: 3
        $x_3_4 = "credicarditau.com.br" wide //weight: 3
        $x_3_5 = " C-A-R-D-S - I-T-A-" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 3 of ($x_3_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Killfiles_U_2147612081_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killfiles.U"
        threat_id = "2147612081"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killfiles"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {eb 09 8b 45 b4 83 c0 01 89 45 b4 83 7d b4 1b 7d 10 8b 4d b4 8b 55 08 c7 44 8a 38 ?? ?? ?? 00}  //weight: 10, accuracy: Low
        $x_1_2 = "\\Device\\HarddiskVolume1\\WINDOWS\\Downloaded Program Files\\gbieh" wide //weight: 1
        $x_1_3 = "\\Device\\HarddiskVolume1\\Arquivos de Programas\\GbPlugin\\" wide //weight: 1
        $x_1_4 = {64 3a 5c 70 72 6f 67 73 5c 67 62 7a 69 6e 68 6f 5c 6f 62 6a 63 68 6b [0-10] 5c 69 33 38 36 5c 44 72 69 76 65 72 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Killfiles_AN_2147627037_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killfiles.AN"
        threat_id = "2147627037"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killfiles"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 72 6f 63 65 73 73 33 32 46 69 72 73 74 [0-4] 6b 65 72 6e 65 6c 33 32 [0-4] 43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 [0-4] 69 6e 20 66 69 6c 74 65 72 [0-4] 6f 70 65 6e}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 6a 00 68 00 90 00 00 53 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {6a 00 6a 00 68 00 b0 00 00 53 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Killfiles_BI_2147627213_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killfiles.BI"
        threat_id = "2147627213"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killfiles"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "del %systemroot%\\system32\\iniuser1.exe" ascii //weight: 1
        $x_1_2 = "del %systemroot%\\system32\\ftp.exe" ascii //weight: 1
        $x_1_3 = "del %systemroot%\\system32\\tftp.exe" ascii //weight: 1
        $x_1_4 = "del %systemroot%\\system32\\cscript.exe" ascii //weight: 1
        $x_1_5 = "del %systemroot%\\system32\\msconfig.exe" ascii //weight: 1
        $x_1_6 = "del %systemroot%\\system32\\at.exe" ascii //weight: 1
        $x_1_7 = "del %systemroot%\\system32\\query.exe" ascii //weight: 1
        $x_1_8 = "del %systemroot%\\system32\\iniuser1stat.exe" ascii //weight: 1
        $x_2_9 = "iniuser1 user kevin /del" ascii //weight: 2
        $x_2_10 = "iniuser1 user iisadmin /del" ascii //weight: 2
        $x_2_11 = "Kill.bat" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 7 of ($x_1_*))) or
            ((3 of ($x_2_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Killfiles_BI_2147627213_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killfiles.BI"
        threat_id = "2147627213"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killfiles"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 95 6c fe ff ff 8b 02 89 85 bc fe ff ff c7 85 f0 fe ff ff ?? ?? 40 00 c7 85 e8 fe ff ff 08 00 00 00 c7 85 00 ff ff ff 02 00 00 00 c7 85 f8 fe ff ff 02 00 00 00 8d 4d 8c 51 b8 10 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 45 fc 1d 00 00 00 8d 4d cc 89 8d 00 ff ff ff c7 85 f8 fe ff ff 08 40 00 00 6a 00 8d 95 f8 fe ff ff 52}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Killfiles_ET_2147627549_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killfiles.ET"
        threat_id = "2147627549"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killfiles"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\native2\\obj\\i386\\delicious.pdb" ascii //weight: 1
        $x_1_2 = "NtDeleteFile" ascii //weight: 1
        $x_1_3 = "NtTerminateProcess" ascii //weight: 1
        $x_1_4 = "GbPlugin\\" wide //weight: 1
        $x_1_5 = {67 00 62 00 70 00 73 00 76 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Killfiles_CG_2147642073_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killfiles.CG"
        threat_id = "2147642073"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killfiles"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "echo WARNING VIRUS HAS BEEN DETECTED" ascii //weight: 1
        $x_1_2 = "del %systemdrive%\\*.* /s /f /q" ascii //weight: 1
        $x_1_3 = "start %windir%\\System32\\rundll32.exe user32.dll, LockWorkStation" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Killfiles_CX_2147654578_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killfiles.CX"
        threat_id = "2147654578"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killfiles"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 65 6c 20 2f 66 20 2f 73 20 2f 71 20 25 73 79 73 74 65 6d 64 72 69 76 65 25 2a 2e ?? ?? ?? [0-16] 63 6f 6c 6f 72 20 31 66 [0-16] 54 69 74 6c 65 20 d5 e2 ca c7 b2 a1 b6 be 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Killfiles_EE_2147718584_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Killfiles.EE"
        threat_id = "2147718584"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Killfiles"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {64 65 6c 20 2a 2e 2a 20 2f 51 20 2f 53 00 63 6c 73 00}  //weight: 1, accuracy: High
        $x_1_2 = {53 74 61 72 74 69 6e 67 20 4e 65 65 64 20 46 6f 72 20 53 70 65 65 64 3a 20 52 69 76 61 6c 73 2e 2e 2e 00 63 64 2e 2e 00}  //weight: 1, accuracy: High
        $x_1_3 = {0f 94 c0 84 c0 75 c8 b8 00 00 00 00 c9 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

