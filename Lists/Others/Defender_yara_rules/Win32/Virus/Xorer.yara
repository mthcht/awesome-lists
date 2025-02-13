rule Virus_Win32_Xorer_A_2147599575_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Xorer.A"
        threat_id = "2147599575"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Xorer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {58 4f 52 00 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 00 00 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 00 00 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {72 61 64 69 6f 00 00 00 54 79 70 65 00 00 00 00 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {53 74 61 72 74 75 70 [0-2] 00 25 63 25 63 25 63 74 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 00}  //weight: 1, accuracy: Low
        $x_1_4 = {70 61 67 65 66 69 6c 65 2e 70 69 66 00}  //weight: 1, accuracy: High
        $x_1_5 = {63 61 63 6c 73 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {72 65 67 73 76 72 33 32 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Xorer_B_2147600505_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Xorer.B"
        threat_id = "2147600505"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Xorer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {bf 38 a5 00 10 f2 ae f7 d1 2b f9 8b d9 8b f7 83 c9 ff 8b fa f2 ae 8b cb 4f c1 e9 02 f3 a5 8b cb 8d 54 24 3c 83 e1 03 f3 a4 8d bc 24 10 05 00 00 83 c9 ff f2 ae f7 d1 2b f9 8b c1 8b f7}  //weight: 1, accuracy: High
        $x_1_2 = {bf 2c a5 00 10 83 c9 ff f2 ae f7 d1 2b f9 c6 44 24 3f 00 8b f7 8b d9 8b fa 83 c9 ff f2 ae 8b cb 4f c1 e9 02 f3 a5 8b cb 8d 54 24 3c 83 e1 03 f3 a4 8d bc 24 10 05 00 00 83 c9 ff f2 ae f7 d1 2b f9 8b c1 8b f7 8b fa 8d 54 24 3c c1 e9 02 f3 a5 8b c8 33 c0 83 e1 03 f3 a4 bf 20 a5 00 10}  //weight: 1, accuracy: High
        $x_1_3 = "\\~.exe" ascii //weight: 1
        $x_1_4 = "037589.log" ascii //weight: 1
        $x_1_5 = "\\com\\lsass.exe" ascii //weight: 1
        $x_1_6 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 43 6f 6e 74 72 6f 6c 5c 53 61 66 65 42 6f 6f 74 5c 4e 65 74 77 6f 72 6b 5c 7b 34 44 33 36 45 39 36 37 2d 45 33 32 35 2d 31 31 43 45 2d 42 46 43 31 2d 30 38 30 30 32 42 45 31 30 33 31 38 7d 00}  //weight: 1, accuracy: High
        $x_1_7 = {72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 41 64 76 61 6e 63 65 64 5c 46 6f 6c 64 65 72 5c 53 75 70 65 72 48 69 64 64 65 6e 00 00 4e 6f 44 72 69 76 65 54 79 70 65 41 75 74 6f 52 75 6e 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Xorer_D_2147601585_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Xorer.D"
        threat_id = "2147601585"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Xorer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {81 c4 7c 44 00 00 c2 10 00 68 ?? ?? ?? ?? 6a 01 6a 00 ff 15 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 3d b7 00 00 00 75 12 5f 5e 5d b8 01 00 00 00 5b 81 c4 7c 44 00 00 c2 10 00}  //weight: 2, accuracy: Low
        $x_2_2 = {63 73 00 00 63 00 00 00 5c 00 00 00 65 78 65 00 73 73 2e 00 6d 5c 00 00}  //weight: 2, accuracy: High
        $x_1_3 = "xcnbkjwer" ascii //weight: 1
        $x_1_4 = "MSICTFIME SMSS" ascii //weight: 1
        $x_1_5 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_6 = "MCI Program Com Application" ascii //weight: 1
        $x_1_7 = {00 58 4f 52 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Virus_Win32_Xorer_E_2147601593_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Xorer.E"
        threat_id = "2147601593"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Xorer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {50 56 57 ff 15 ?? ?? ?? ?? 8b f8 33 c0 85 ff 0f 95 c0 eb 0d 8d 4c 24 ?? 51 56 57 ff 15 ?? ?? ?? ?? 85 c0 74 3d 33 db eb 45}  //weight: 2, accuracy: Low
        $x_2_2 = {6a 00 68 ff 0f 1f 00 ff 15 ?? ?? ?? ?? 8b f0 85 f6 74 09 6a 01 56 ff 15 ?? ?? ?? ?? 56 ff 15 ?? ?? ?? ?? 8b 44 24 ?? 50 6a 00 68 ff 0f 1f 00 ff 15 ?? ?? ?? ?? 8b f0 85 f6}  //weight: 2, accuracy: Low
        $x_2_3 = {00 61 73 73 00 68 74 74 70 3a 2f 2f 00 25 73 2e 25 64 00}  //weight: 2, accuracy: High
        $x_1_4 = "IFOBJ.IfObjPropPage.1" ascii //weight: 1
        $x_1_5 = "WaveOutGetVolume" ascii //weight: 1
        $x_1_6 = "DeleteUrlCacheEntry" ascii //weight: 1
        $x_1_7 = {00 64 61 74 61 2e 67 69 66}  //weight: 1, accuracy: High
        $x_1_8 = {00 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 00}  //weight: 1, accuracy: High
        $x_1_9 = {00 73 76 00 00 67 76 00 00 6d 6d 00 00 67 63 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Virus_Win32_Xorer_H_2147601627_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Xorer.H"
        threat_id = "2147601627"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Xorer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {68 64 64 64 32 33 ff 50 47 57 ff 15 ?? ?? ?? 00 85 c0 a3 ?? ?? ?? 00}  //weight: 2, accuracy: Low
        $x_2_2 = {00 43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 00 [0-3] 00 00 35 00 30 00 36 00}  //weight: 2, accuracy: Low
        $x_2_3 = "KeServiceDescriptorTable" ascii //weight: 2
        $x_1_4 = "DeleteSymbolicLink Fail!" ascii //weight: 1
        $x_1_5 = {5c 00 34 00 36 00 35 00 39 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = "\\Device\\NetApi000" wide //weight: 1
        $x_1_7 = {5c 00 33 00 38 00 39 00 35 00 33 00 00 00}  //weight: 1, accuracy: High
        $x_1_8 = {5c 00 3f 00 3f 00 5c 00 4e 00 65 00 74 00 41 00 70 00 69 00 30 00 30 00 30 00 44 00 4f 00 53 00 00 00}  //weight: 1, accuracy: High
        $x_1_9 = {64 00 64 00 64 00 32 00 2e 00 73 00 79 00 73 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Virus_Win32_Xorer_K_2147601630_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Xorer.K"
        threat_id = "2147601630"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Xorer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c2 10 00 68 ?? ?? ?? 00 6a 01 6a 00 ff 15 ?? ?? ?? 00 ff 15 ?? ?? ?? 00 3d b7 00 00 00 75 12 5f 5e 5d b8 01 00 00 00 5b 81 c4 ?? ?? 00 00 c2 10 00}  //weight: 2, accuracy: Low
        $x_2_2 = "dghauweugsdgerh" ascii //weight: 2
        $x_1_3 = "MSICTFIME SMSS" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_5 = "MCI Program Com Application" ascii //weight: 1
        $x_1_6 = {00 58 4f 52 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Virus_Win32_Xorer_L_2147601633_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Xorer.L"
        threat_id = "2147601633"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Xorer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 00 [0-3] 00 00 35 00 30 00 36 00}  //weight: 2, accuracy: Low
        $x_2_2 = {00 5c 6c 73 00 63 6f 6d 00 25 73 5c 25 73 00}  //weight: 2, accuracy: High
        $x_2_3 = {00 73 76 00 00 67 76 00 00 6d 6d 00 00 67 63 00}  //weight: 2, accuracy: High
        $x_1_4 = {00 61 73 73 00 68 74 74 70 3a 2f 2f 00 25 73 2e 25 64 00}  //weight: 1, accuracy: High
        $x_1_5 = "WaveOutGetVolume" ascii //weight: 1
        $x_1_6 = {00 64 61 74 61 2e 67 69 66}  //weight: 1, accuracy: High
        $x_1_7 = {00 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 00}  //weight: 1, accuracy: High
        $x_1_8 = {00 68 6f 6f 6b 2e 64 6c 6c}  //weight: 1, accuracy: High
        $x_1_9 = "InstallHOOK" ascii //weight: 1
        $x_1_10 = {00 66 67 30 00 30 30 30 2e 63 00}  //weight: 1, accuracy: High
        $x_1_11 = {00 68 74 74 70 3a 2f 2f 00 2e 6c 6f 67 00}  //weight: 1, accuracy: High
        $x_1_12 = {00 72 62 00 00 61 2e 67 69 66 00 00 00 64 61 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Virus_Win32_Xorer_A_2147605915_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Xorer.gen!A"
        threat_id = "2147605915"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Xorer"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "jnjejdjdjijHjrjejpjujSjwjojhjS" ascii //weight: 3
        $x_3_2 = "jujRjojtjujAjejpjyjTjejvjijrjDjojN" ascii //weight: 3
        $x_3_3 = "jsj/PjdjrPjcj/Pjejxjej.jdjmjc" ascii //weight: 3
        $x_3_4 = "jfjijpj.jejljijfjejgjajp" ascii //weight: 3
        $x_2_5 = "%s\\dnsq.dll" ascii //weight: 2
        $x_1_6 = {33 36 30 61 6e 74 69 00}  //weight: 1, accuracy: High
        $x_1_7 = "%s\\037589.log" ascii //weight: 1
        $x_1_8 = {25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 00}  //weight: 1, accuracy: High
        $x_1_9 = "xcgucvnzn" ascii //weight: 1
        $x_1_10 = "%s\\NetApi000.sys" ascii //weight: 1
        $x_1_11 = "shell\\open\\Command=pagefile.pif" ascii //weight: 1
        $x_1_12 = "KeServiceDescriptorTable" ascii //weight: 1
        $x_1_13 = "-r -inul -ibck -y" ascii //weight: 1
        $x_1_14 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\Folder\\SuperHidden" ascii //weight: 1
        $x_1_15 = "cmd.exe /c del /F /Q \"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((3 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Virus_Win32_Xorer_O_2147609419_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Xorer.O"
        threat_id = "2147609419"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Xorer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 7c 24 10 ee be 09 00 75 08 6a 00 ff 15 ?? ?? 40 00 33 c0 c2 10 00 68 ?? ?? 40 00 68 ?? ?? 40 00 ff 15 ?? ?? 40 00 85 c0 75 0c 50 68 ?? ?? 40 00 ff 15 ?? ?? 40 00 33 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Xorer_B_2147614421_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Xorer.gen!B"
        threat_id = "2147614421"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Xorer"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4d 43 49 20 50 72 6f 67 72 61 00}  //weight: 1, accuracy: High
        $x_1_2 = "\\com\\lsass.exe" ascii //weight: 1
        $x_1_3 = "037589.log" ascii //weight: 1
        $x_1_4 = "cmd.exe /c rd /s /q \"" ascii //weight: 1
        $x_1_5 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\Folder\\SuperHidden" ascii //weight: 1
        $x_1_6 = "SYSTEM\\ControlSet001\\Control\\SafeBoot\\Minimal\\{4D36E967-E325-11CE-BFC1-08002BE10318}" ascii //weight: 1
        $x_1_7 = {00 68 6f 6f 6b 2e 64 6c 6c}  //weight: 1, accuracy: High
        $x_1_8 = "InstallHOOK" ascii //weight: 1
        $x_1_9 = "360safe" ascii //weight: 1
        $x_1_10 = "facelesswndproc" ascii //weight: 1
        $x_1_11 = "bitdefender" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Virus_Win32_Xorer_M_2147614422_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Xorer.M!dll"
        threat_id = "2147614422"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Xorer"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 6f 6f 6b 2e 64 6c 6c 00 49 6e 73 74 61 6c 6c 48 4f 4f 4b 00 55 6e 69 6e 73 74 61 6c 6c 48 4f 4f 4b 00}  //weight: 1, accuracy: High
        $x_1_2 = "MCI Progr" ascii //weight: 1
        $x_1_3 = "shutdown.exe -r -f -t 0" ascii //weight: 1
        $x_1_4 = "\\~.exe" ascii //weight: 1
        $x_1_5 = "\\com\\lsass.exe" ascii //weight: 1
        $x_1_6 = "WinExec" ascii //weight: 1
        $x_1_7 = "FindWindowA" ascii //weight: 1
        $x_1_8 = "SetWindowsHookExA" ascii //weight: 1
        $x_1_9 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders" ascii //weight: 1
        $x_1_10 = "Startup" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Xorer_Y_2147614423_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Xorer.Y"
        threat_id = "2147614423"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Xorer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 8d 80 fe ff ff 51 8d 4d d8 e8 ?? ?? 00 00 6a 00 68 ?? ?? 40 00 6a 00 6a 00 ff 15 ?? ?? 40 00 68 ?? ?? 40 00 8d 4d d8 89 45 c4 e8 ?? ?? 00 00 83 f8 ff 0f 84 34 02 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Xorer_I_2147626649_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Xorer.gen!I"
        threat_id = "2147626649"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Xorer"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[AutoRun]" ascii //weight: 1
        $x_2_2 = "shellexecute=pagefile.pif" ascii //weight: 2
        $x_1_3 = {61 66 74 65 72 42 65 67 69 6e 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {7e 2e 70 69 66 00 00}  //weight: 1, accuracy: High
        $x_1_5 = "_system~.ini" ascii //weight: 1
        $x_1_6 = "FloodFill" ascii //weight: 1
        $x_1_7 = {49 45 46 72 61 6d 65 00}  //weight: 1, accuracy: High
        $x_2_8 = "jljpjxjE" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

