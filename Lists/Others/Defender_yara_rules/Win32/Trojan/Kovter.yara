rule Trojan_Win32_Kovter_A_2147679327_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kovter.A"
        threat_id = "2147679327"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kovter"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 fc 8a 44 18 ff 24 0f 8b 55 f8 8a 54 32 ff 80 e2 0f 32 c2 88 45 f3 8d 45 fc e8 ?? ?? ?? ?? 8b 55 fc 8a 54 1a ff 80 e2 f0}  //weight: 1, accuracy: Low
        $x_1_2 = {6d 6f 64 65 3d 33 26 63 6d 64 69 64 3d 00}  //weight: 1, accuracy: High
        $x_1_3 = {6d 00 6f 00 64 00 65 00 3d 00 31 00 26 00 55 00 49 00 44 00 3d 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {26 00 63 00 6f 00 6f 00 6b 00 3d 00 00 00 00 00 0e 00 00 00 26 00 66 00 63 00 6f 00 6f 00 6b 00 3d 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {6c 00 69 00 6d 00 69 00 74 00 62 00 6c 00 61 00 6e 00 6b 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 75 00 73 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {4f 00 70 00 65 00 72 00 61 00 5c 00 4f 00 70 00 65 00 72 00 61 00 5c 00 63 00 6f 00 6f 00 6b 00 69 00 65 00 73 00 34 00 2e 00 64 00 61 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {72 65 6d 69 78 73 69 64 00}  //weight: 1, accuracy: High
        $x_1_8 = {5c 00 47 00 6f 00 6f 00 67 00 6c 00 65 00 5c 00 43 00 68 00 72 00 6f 00 6d 00 65 00 5c 00 55 00 73 00 65 00 72 00 20 00 44 00 61 00 74 00 61 00 5c 00 44 00 65 00 66 00 61 00 75 00 6c 00 74 00 5c 00 43 00 6f 00 6f 00 6b 00 69 00 65 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_9 = {42 00 75 00 6c 00 6c 00 47 00 75 00 61 00 72 00 64 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_10 = {43 00 4c 00 50 00 53 00 4c 00 53 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_11 = {73 00 70 00 69 00 64 00 65 00 72 00 61 00 67 00 65 00 6e 00 74 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_12 = {2f 00 61 00 6c 00 5f 00 67 00 72 00 6f 00 75 00 70 00 73 00 2e 00 70 00 68 00 70 00 00 00}  //weight: 1, accuracy: High
        $x_1_13 = "onclick=\"Groups.enter(this," ascii //weight: 1
        $x_1_14 = {61 63 74 3d 61 5f 65 6e 74 65 72 26 61 6c 3d 31 26 68 61 73 68 3d 00}  //weight: 1, accuracy: High
        $x_1_15 = {3e 00 3e 00 70 00 61 00 74 00 68 00 00 00}  //weight: 1, accuracy: High
        $x_1_16 = {3e 00 3e 00 75 00 70 00 64 00 00 00}  //weight: 1, accuracy: High
        $x_1_17 = "Hyte342FJrOd9!" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (12 of ($x*))
}

rule Trojan_Win32_Kovter_B_2147681945_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kovter.B"
        threat_id = "2147681945"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kovter"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "120"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {00 00 6d 00 6f 00 64 00 65 00 3d 00 32 00 26 00 55 00 49 00 44 00 3d 00 00 00}  //weight: 100, accuracy: High
        $x_100_2 = {00 6d 6f 64 65 3d 32 26 55 49 44 3d 00}  //weight: 100, accuracy: High
        $x_10_3 = {00 41 6e 74 69 53 75 6e 62 65 6c 74 53 61 6e 64 62 6f 78 69 65 00}  //weight: 10, accuracy: High
        $x_10_4 = {00 00 4f 00 70 00 65 00 72 00 61 00 5c 00 4f 00 70 00 65 00 72 00 61 00 5c 00 63 00 6f 00 6f 00 6b 00 69 00 65 00 73 00 34 00 2e 00 64 00 61 00 74 00 00 00}  //weight: 10, accuracy: High
        $x_10_5 = {26 4f 53 62 69 74 3d [0-16] 00 26 61 66 66 5f 69 64 3d 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 2 of ($x_10_*))) or
            ((2 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Kovter_C_2147684944_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kovter.C"
        threat_id = "2147684944"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kovter"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 fc 8a 44 18 ff 24 0f 8b 55 f8 8a 54 32 ff 80 e2 0f 32 c2 88 45 f3 8d 45 fc e8 ?? ?? ?? ?? 8b 55 fc 8a 54 1a ff 80 e2 f0}  //weight: 10, accuracy: Low
        $x_1_2 = {3e 3e 75 70 64 69 64 00}  //weight: 1, accuracy: High
        $x_1_3 = {6d 6f 64 65 3d 32 26 64 6f 6e 65 3d 31 26 63 6d 64 69 64 3d 00}  //weight: 1, accuracy: High
        $x_1_4 = {61 00 64 00 64 00 68 00 65 00 61 00 64 00 65 00 72 00 73 00 3d 00 31 00 26 00 55 00 49 00 44 00 3d 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {6d 6f 64 65 3d 34 26 55 49 44 3d 00}  //weight: 1, accuracy: High
        $x_1_6 = {26 4f 53 62 69 74 3d 00}  //weight: 1, accuracy: High
        $x_1_7 = {6c 00 69 00 6d 00 69 00 74 00 62 00 6c 00 61 00 6e 00 6b 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 75 00 73 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_8 = "try {jwplayer().play()}" ascii //weight: 1
        $x_1_9 = {3c 61 20 68 72 65 66 3d 27 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 27 3e 63 6c 69 63 6b 3c 2f 61 3e}  //weight: 1, accuracy: Low
        $x_1_10 = {2e 52 75 6e 28 22 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 69 65 78 20 24 65 6e 76 3a}  //weight: 1, accuracy: Low
        $x_1_11 = {6d 73 68 74 61 20 22 6a 61 76 61 73 63 72 69 70 74 3a [0-16] 3d 6e 65 77 20 41 63 74 69 76 65 58 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 3b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Kovter_E_2147688122_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kovter.E"
        threat_id = "2147688122"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kovter"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 fc 8a 44 18 ff 24 0f 8b 55 f8 8a 54 32 ff 80 e2 0f 32 c2 88 45 f3 8d 45 fc e8 ?? ?? ?? ?? 8b 55 fc 8a 54 1a ff 80 e2 f0}  //weight: 1, accuracy: Low
        $x_1_2 = {50 6a 00 6a 00 6a 24 6a 00 ff d6 50 e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 85 c0 74 0a 8b c3}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 00 6a 02 6a 02 6a 00 6a 00 68 00 00 00 40 8b 45 fc e8 ?? ?? ?? ?? 8b d8 53 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? 53 e8 ?? ?? ?? ?? 53 e8}  //weight: 1, accuracy: Low
        $x_1_4 = {3e 00 3e 00 70 00 61 00 74 00 68 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Kovter_C_2147691570_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kovter.C!!Kovter.gen!A"
        threat_id = "2147691570"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kovter"
        severity = "Critical"
        info = "Kovter: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 fc 8a 44 18 ff 24 0f 8b 55 f8 8a 54 32 ff 80 e2 0f 32 c2 88 45 f3 8d 45 fc e8 ?? ?? ?? ?? 8b 55 fc 8a 54 1a ff 80 e2 f0}  //weight: 10, accuracy: Low
        $x_1_2 = {3e 00 3e 00 75 00 70 00 64 00 69 00 64 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {6d 00 6f 00 64 00 65 00 3d 00 32 00 26 00 64 00 6f 00 6e 00 65 00 3d 00 31 00 26 00 63 00 6d 00 64 00 69 00 64 00 3d 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {61 00 64 00 64 00 68 00 65 00 61 00 64 00 65 00 72 00 73 00 3d 00 31 00 26 00 55 00 49 00 44 00 3d 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {6d 00 6f 00 64 00 65 00 3d 00 34 00 26 00 55 00 49 00 44 00 3d 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {26 00 4f 00 53 00 62 00 69 00 74 00 3d 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {6c 00 69 00 6d 00 69 00 74 00 62 00 6c 00 61 00 6e 00 6b 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 75 00 73 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_8 = "try {jwplayer().play()}" ascii //weight: 1
        $x_1_9 = {3c 61 20 68 72 65 66 3d 27 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 27 3e 63 6c 69 63 6b 3c 2f 61 3e}  //weight: 1, accuracy: Low
        $x_1_10 = {2e 52 75 6e 28 22 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 69 65 78 20 24 65 6e 76 3a}  //weight: 1, accuracy: Low
        $x_1_11 = {6d 73 68 74 61 20 22 6a 61 76 61 73 63 72 69 70 74 3a [0-16] 3d 6e 65 77 20 41 63 74 69 76 65 58 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 3b}  //weight: 1, accuracy: Low
        $x_1_12 = {3d 6e 65 77 25 32 30 41 63 74 69 76 65 58 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 3b 00}  //weight: 1, accuracy: High
        $x_1_13 = {3e 00 3e 00 70 00 61 00 74 00 68 00 00 00}  //weight: 1, accuracy: High
        $x_1_14 = {8a 54 32 ff 80 e2 0f 32 c2 88 45 f3}  //weight: 1, accuracy: High
        $x_1_15 = {33 c0 8a 03 ba 02 00 00 00 e8 ?? ?? ?? ?? 8b 55 ?? 8b c7 e8 ?? ?? ?? ?? 43 4e 75 e1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((14 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Kovter_E_2147691571_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kovter.E!!Kovter.gen!A"
        threat_id = "2147691571"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kovter"
        severity = "Critical"
        info = "Kovter: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 fc 8a 44 18 ff 24 0f 8b 55 f8 8a 54 32 ff 80 e2 0f 32 c2 88 45 f3 8d 45 fc e8 ?? ?? ?? ?? 8b 55 fc 8a 54 1a ff 80 e2 f0}  //weight: 1, accuracy: Low
        $x_1_2 = {50 6a 00 6a 00 6a 24 6a 00 ff d6 50 e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 85 c0 74 0a 8b c3}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 00 6a 02 6a 02 6a 00 6a 00 68 00 00 00 40 8b 45 fc e8 ?? ?? ?? ?? 8b d8 53 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? 53 e8 ?? ?? ?? ?? 53 e8}  //weight: 1, accuracy: Low
        $x_1_4 = {3e 00 3e 00 70 00 61 00 74 00 68 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Kovter_G_2147695443_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kovter.G"
        threat_id = "2147695443"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kovter"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 00 73 00 68 00 74 00 61 00 [0-16] 6a 00 61 00 76 00 61 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00 [0-255] 6e 00 65 00 77 00 20 00 61 00 63 00 74 00 69 00 76 00 65 00 78 00 6f 00 62 00 6a 00 65 00 63 00 74 00 28 00}  //weight: 1, accuracy: Low
        $x_1_2 = {6d 00 73 00 68 00 74 00 61 00 [0-16] 6a 00 61 00 76 00 61 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00 [0-255] 67 00 65 00 74 00 6f 00 62 00 6a 00 65 00 63 00 74 00 28 00}  //weight: 1, accuracy: Low
        $x_1_3 = {6d 00 73 00 68 00 74 00 61 00 [0-16] 76 00 62 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00 [0-255] 65 00 78 00 65 00 63 00 75 00 74 00 65 00 28 00 [0-255] 67 00 65 00 74 00 6f 00 62 00 6a 00 65 00 63 00 74 00 28 00}  //weight: 1, accuracy: Low
        $x_1_4 = {6d 00 73 00 68 00 74 00 61 00 [0-16] 76 00 62 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00 [0-255] 65 00 78 00 65 00 63 00 75 00 74 00 65 00 28 00 [0-255] 63 00 72 00 65 00 61 00 74 00 65 00 6f 00 62 00 6a 00 65 00 63 00 74 00 28 00}  //weight: 1, accuracy: Low
        $n_50_5 = "Wscript.Shell\"\").Run \"\"robocopy.exe \"" wide //weight: -50
        $n_50_6 = "su8000005011.ad.ing.net\\DMLConfig\\FMO" wide //weight: -50
        $n_50_7 = "ffwin.fujifilm.co.jp\\netlogon" wide //weight: -50
        $n_50_8 = "util\\HpseuHostLAuncher.ps1" wide //weight: -50
        $n_50_9 = "MSHTA.EXE javascript:new ActiveXObject('Scripting.FileSystemObject').GetStandardStream(0).ReadAll()" wide //weight: -50
        $n_50_10 = "innerText=new ActiveXObject('Scripting.FileSystemObject').GetStandardStream(0).ReadAll()" wide //weight: -50
        $n_50_11 = {49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 29 00 2e 00 50 00 75 00 74 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 79 00 28 00 27 00 ?? ?? ?? ?? ?? ?? 27 00 2c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 29 00 3b 00 77 00 69 00 6e 00 64 00 6f 00 77 00 2e 00 72 00 65 00 73 00 69 00 7a 00 65 00 54 00 6f 00 28 00 35 00 30 00 30 00 2c 00 32 00 35 00 30 00 29 00 3b 00 77 00 69 00 6e 00 64 00 6f 00 77 00 2e 00 6d 00 6f 00 76 00 65 00 54 00 6f 00 28 00 2c 00 29 00}  //weight: -50, accuracy: Low
        $n_50_12 = "mshta vbscript:Execute(\"CreateObject(\"\"Wscript.shell\"\").run (\"\"powershell.exe -command net use H: \\\\filecl01fsh\\users$" wide //weight: -50
        $n_50_13 = "mshta.exe javascript:var sh=new ActiveXObject('WScript.Shell'); sh.Popup('" wide //weight: -50
        $n_50_14 = "vbscript:Execute(On Error Resume Next:call CreateObject(WSCript.shell).Run(%systemroot%\\system32\\reg.exe &amp" wide //weight: -50
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

rule Trojan_Win32_Kovter_H_2147707267_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kovter.H"
        threat_id = "2147707267"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kovter"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 45 fc 8a 44 18 ff 24 0f 8b 55 f8 8a 54 32 ff 80 e2 0f 32 c2 88 45 f3 8d 45 fc e8 ?? ?? ?? ?? 8b 55 fc 8a 54 1a ff 80 e2 f0}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Kovter_H_2147707267_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kovter.H"
        threat_id = "2147707267"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kovter"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 61 00 76 00 61 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00 [0-255] 6e 00 65 00 77 00 20 00 61 00 63 00 74 00 69 00 76 00 65 00 78 00 6f 00 62 00 6a 00 65 00 63 00 74 00 28 00 22 00 77 00 73 00 63 00 72 00 69 00 70 00 74 00 2e 00 73 00 68 00 65 00 6c 00 6c 00 22 00}  //weight: 1, accuracy: Low
        $x_10_2 = "RegRead(\"hkcu\\software" wide //weight: 10
        $n_50_3 = "Wscript.Shell\"\").Run \"\"robocopy.exe \"" wide //weight: -50
        $n_50_4 = "su8000005011.ad.ing.net\\DMLConfig\\FMO" wide //weight: -50
        $n_50_5 = "ffwin.fujifilm.co.jp\\netlogon\\webvpn_logon" wide //weight: -50
        $n_50_6 = "util\\HpseuHostLAuncher.ps1" wide //weight: -50
        $n_50_7 = "MSHTA.EXE javascript:new ActiveXObject('Scripting.FileSystemObject').GetStandardStream(0).ReadAll()" wide //weight: -50
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_Kovter_I_2147707411_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kovter.I"
        threat_id = "2147707411"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kovter"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 54 32 ff 80 e2 0f 32 c2 88 45 f3}  //weight: 1, accuracy: High
        $x_1_2 = {33 c0 8a 03 ba 02 00 00 00 e8 ?? ?? ?? ?? 8b 55 ?? 8b c7 e8 ?? ?? ?? ?? 43 4e 75 e1}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 6e 65 77 25 32 30 41 63 74 69 76 65 58 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 3b 00}  //weight: 1, accuracy: High
        $x_1_4 = "itco\\infect\\bin" ascii //weight: 1
        $x_1_5 = "if exist \"%S\" goto :REDO" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Kovter_I_2147707411_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kovter.I"
        threat_id = "2147707411"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kovter"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "DisableRealtimeMonitoring" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\Wow6432Node\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection" ascii //weight: 1
        $x_1_3 = "NoAutoUpdate" ascii //weight: 1
        $x_1_4 = "%s\\%s.hta" ascii //weight: 1
        $x_1_5 = "killall" ascii //weight: 1
        $x_1_6 = {5c 41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c [0-32] 2e 68 74 61}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Kovter_K_2147711063_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kovter.K!bit"
        threat_id = "2147711063"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kovter"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {22 29 00 53 79 73 74 65 6d 2e 64 6c 6c 00 03 95 80 5c 53 79 73 74 65 6d 2e 64 6c 6c}  //weight: 1, accuracy: High
        $x_1_2 = {73 70 6f 72 74 73 77 6f 6d 61 6e 2e 64 6c 6c 00 43 6f 6e 73 63 72 69 70 74 50 72 6f 74 6f 7a 6f 61 6e 42 65 64 66 65 6c 6c 6f 77 00 73 70 6f 72 74 73 77 6f 6d 61 6e 3a 3a 43 65 6e 74 6f}  //weight: 1, accuracy: High
        $x_1_3 = {00 43 72 61 76 61 74 57 61 72 72 61 67 61 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Kovter_M_2147711157_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kovter.M"
        threat_id = "2147711157"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kovter"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 8b ca 8b d8 d3 e3 b9 20 00 00 00 2b ca d3 e8 0b d8 8b c3}  //weight: 1, accuracy: High
        $x_1_2 = {8a 84 85 e8 fb ff ff 8b 55 ec 30 04 3a 47 ff 4d e8}  //weight: 1, accuracy: High
        $x_1_3 = {8b 45 fc 8a 44 18 ff 24 0f 8b 55 f8 8a 54 32 ff 80 e2 0f 32 c2 88 45 f3}  //weight: 1, accuracy: High
        $x_1_4 = {33 c0 8a 03 ba 02 00 00 00 e8 ?? ?? ?? ?? 8b 55 ?? 8b c7 e8 ?? ?? ?? ?? 43 4e 75 e1}  //weight: 1, accuracy: Low
        $x_1_5 = "try {jwplayer().play()}" ascii //weight: 1
        $x_1_6 = {3e 00 3e 00 70 00 61 00 74 00 68 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {2e 52 75 6e 28 22 [0-16] 69 65 78 20 24 65 6e 76 3a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Kovter_I_2147727345_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kovter.I!!Kovter.gen!A"
        threat_id = "2147727345"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kovter"
        severity = "Critical"
        info = "Kovter: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 54 32 ff 80 e2 0f 32 c2 88 45 f3}  //weight: 1, accuracy: High
        $x_1_2 = {33 c0 8a 03 ba 02 00 00 00 e8 ?? ?? ?? ?? 8b 55 ?? 8b c7 e8 ?? ?? ?? ?? 43 4e 75 e1}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 6e 65 77 25 32 30 41 63 74 69 76 65 58 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 3b 00}  //weight: 1, accuracy: High
        $x_1_4 = "itco\\infect\\bin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Kovter_J_2147727506_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kovter.J!!Kovter.gen!B"
        threat_id = "2147727506"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kovter"
        severity = "Critical"
        info = "Kovter: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "B: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "7562@3B45E129B93" ascii //weight: 1
        $x_1_2 = "@ouhKndCny" ascii //weight: 1
        $x_1_3 = "@ouh@mmEdctffdsr" ascii //weight: 1
        $x_1_4 = "@ouhSGQ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Kovter_R_2147740356_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kovter.R!cmd"
        threat_id = "2147740356"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kovter"
        severity = "Critical"
        info = "cmd: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\mshta.exe" wide //weight: 1
        $x_1_2 = {6a 00 61 00 76 00 61 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00 [0-48] 3d 00 6e 00 65 00 77 00 20 00 61 00 63 00 74 00 69 00 76 00 65 00 78 00 6f 00 62 00 6a 00 65 00 63 00 74 00 28 00 [0-4] 77 00 73 00 63 00 72 00 69 00 70 00 74 00 2e 00 73 00 68 00 65 00 6c 00 6c 00}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 00 72 00 65 00 67 00 72 00 65 00 61 00 64 00 28 00 [0-4] 68 00 6b 00 63 00 75 00 5c 00 73 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00}  //weight: 1, accuracy: Low
        $x_1_4 = ";eval(" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Kovter_S_2147740502_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kovter.S"
        threat_id = "2147740502"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kovter"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 72 28 6a 18 59 31 ff 31 c0 ac 3c 61 7c 02 2c 20 c1 cf 0d 01 c7 e2 f0 81 ff ?? ?? ?? ?? 8b 5a 10 8b 12 75 db}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 fc 89 45 d4 8b 45 d4 66 81 38 4d 5a 0f 85 0f 02 00 00 8b 45 fc 33 d2 52 50 8b 45 d4 8b 40 3c 99 03 04 24 13 54 24 04 83 c4 08 89 45 d0 8b 45 d0 81 38 50 45 00 00 0f 85 e5 01 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {c6 85 2f ff ff ff 61 c6 85 30 ff ff ff 64 c6 85 31 ff ff ff 76 c6 85 32 ff ff ff 61 c6 85 33 ff ff ff 70 c6 85 34 ff ff ff 69 c6 85 35 ff ff ff 33 c6 85 36 ff ff ff 32 c6 85 37 ff ff ff 2e c6 85 38 ff ff ff 64 c6 85 39 ff ff ff 6c c6 85 3a ff ff ff 6c c6 85 3b ff ff ff 00}  //weight: 1, accuracy: High
        $x_1_4 = {03 cb 81 39 52 65 67 4f 75 ?? 8d 41 04 81 38 70 65 6e 4b 75 50}  //weight: 1, accuracy: Low
        $x_1_5 = {81 39 45 78 69 74 75}  //weight: 1, accuracy: High
        $x_1_6 = {81 38 50 72 6f 63 75}  //weight: 1, accuracy: High
        $x_1_7 = "shell<<::>>" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Kovter_S_2147740503_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kovter.S!psh"
        threat_id = "2147740503"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kovter"
        severity = "Critical"
        info = "psh: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ";}[Byte[]] $" ascii //weight: 1
        $x_1_2 = ".invoke(0," ascii //weight: 1
        $x_1_3 = {2e 00 67 00 65 00 74 00 6d 00 65 00 74 00 68 00 6f 00 64 00 28 00 [0-4] 67 00 65 00 74 00 70 00 72 00 6f 00 63 00 61 00 64 00 64 00 72 00 65 00 73 00 73 00 [0-4] 29 00 2e 00 69 00 6e 00 76 00 6f 00 6b 00 65 00}  //weight: 1, accuracy: Low
        $x_1_4 = {2e 67 65 74 6d 65 74 68 6f 64 28 [0-4] 67 65 74 70 72 6f 63 61 64 64 72 65 73 73 [0-4] 29 2e 69 6e 76 6f 6b 65}  //weight: 1, accuracy: Low
        $x_1_5 = "0xc6,0x85,0x2f,0xff,0xff,0xff,0x61,0xc6,0x85,0x30,0xff,0xff,0xff,0x64,0xc6,0x85,0x31,0xff,0xff,0xff,0x76" ascii //weight: 1
        $x_1_6 = "0x03,0xcb,0x81,0x39,0x52,0x65,0x67,0x4f" ascii //weight: 1
        $x_1_7 = "0x8d,0x41,0x04,0x81,0x38,0x70,0x65,0x6e,0x4b" ascii //weight: 1
        $x_1_8 = "0x81,0x39,0x45,0x78,0x69,0x74,0x75" ascii //weight: 1
        $x_1_9 = "0x81,0x38,0x50,0x72,0x6F,0x63,0x75" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Kovter_L_2147752413_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kovter.L"
        threat_id = "2147752413"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kovter"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 00 73 00 68 00 74 00 61 00 [0-16] 6a 00 61 00 76 00 61 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00 [0-255] 67 00 65 00 74 00 6f 00 62 00 6a 00 65 00 63 00 74 00 28 00}  //weight: 1, accuracy: Low
        $x_1_2 = {6d 00 73 00 68 00 74 00 61 00 [0-16] 76 00 62 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00 [0-255] 65 00 78 00 65 00 63 00 75 00 74 00 65 00 28 00 [0-255] 67 00 65 00 74 00 6f 00 62 00 6a 00 65 00 63 00 74 00 28 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Kovter_RPT_2147828346_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kovter.RPT!MTB"
        threat_id = "2147828346"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kovter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 00 f8 66 4d 98 [0-21] c7 00 65 f2 0f fc [0-21] c7 00 e4 66 c9 66 [0-21] c7 00 66 0f e2 ed [0-21] c7 00 80 ef 5d 63 [0-21] c7 00 0b 13 a9 e7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Kovter_LK_2147846770_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kovter.LK!MTB"
        threat_id = "2147846770"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kovter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 db 8a 19 c1 eb 04 8a 9b ?? ?? ?? ?? 88 1e 46 8a 19 80 e3 0f 81 e3 ff 00 00 00 8a 9b ?? ?? ?? ?? 88 1e 46 41 4f 75 d8}  //weight: 1, accuracy: Low
        $x_1_2 = "222.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Kovter_AKVT_2147952920_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kovter.AKVT!MTB"
        threat_id = "2147952920"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kovter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {33 d2 52 50 8b c6 c1 e0 02 99 03 04 24 13 54 24 04 83 c4 08 03 04 24 13 54 24 04 83 c4 08 8b 08 03 4d fc 81 39 4c 6f 61 64 75 56 8d 41 04}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

