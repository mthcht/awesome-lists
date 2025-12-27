rule Trojan_Win32_Dexphot_E_2147730697_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dexphot.E!!Dexphot.E"
        threat_id = "2147730697"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dexphot"
        severity = "Critical"
        info = "Dexphot: an internal category used to refer to some threats"
        info = "E: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 53 33 db 8b 45 0c 83 f8 11 7f 0c 74 30 83 e8 0f 74 42 48 74 36 eb 48}  //weight: 1, accuracy: High
        $x_1_2 = {83 e8 16 74 28 2d fa 00 00 00 75 3c 6a 01 68 ff 04 00 00 e8 ?? ?? ff ff 6a 01 68 ff 03 00 00 e8 ?? ?? ff ff eb 22}  //weight: 1, accuracy: Low
        $x_1_3 = "Toolhelp32ReadProcessMemory" ascii //weight: 1
        $x_1_4 = "Process32First" ascii //weight: 1
        $x_1_5 = "Process32Next" ascii //weight: 1
        $x_1_6 = "Thread32First" ascii //weight: 1
        $x_1_7 = "Thread32Next" ascii //weight: 1
        $x_1_8 = "EnumProcess" ascii //weight: 1
        $x_1_9 = "GetMappedFileName" ascii //weight: 1
        $x_1_10 = "GetDeviceDriverBaseName" ascii //weight: 1
        $x_1_11 = "GetDeviceDriverFileName" ascii //weight: 1
        $x_1_12 = "EnumDeviceDrivers" ascii //weight: 1
        $x_1_13 = "GetProcessMemoryInfo" ascii //weight: 1
        $x_1_14 = {78 55 6e 7a 72 54 00 00 ff ff ff ff 02 00 00 00 63 47 00 00 ff ff ff ff 04 00 00 00 39 33 5a 58 00 00 00 00 ff ff ff ff 03 00 00 00 4a 7a 61 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dexphot_2147731153_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dexphot"
        threat_id = "2147731153"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dexphot"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ocessMdinocessMidssMininocessMindocessMininocessMinin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dexphot_2147731153_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dexphot"
        threat_id = "2147731153"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dexphot"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 38 50 45 00 00 74 0f b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? e9 ?? ?? ?? ?? 8b 45 ?? 50 68 00 20 00 00 8b 45 ?? 8b 40 50 50 8b 45 ?? 8b 40 34 50 6a ff e8}  //weight: 1, accuracy: Low
        $x_1_2 = {30 02 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 77 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 72 ?? 33 c9 b2 01 a1 1d 00 a0 ?? ?? ?? ?? 02 05 ?? ?? ?? ?? 02 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 03 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dexphot_2147731153_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dexphot"
        threat_id = "2147731153"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dexphot"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 49 43 34 00 00 00 00 41 49 43 35 00 00 00 00 41 49 43 36 00 00 00 00 ff ff ff ff 10 00 00 00 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 00 00 00 00 41 49 43 37 00 00 00 00 41 49 43 38 00 00 00 00 41 49 43 39 00 00 00 00 41 49 43 39 2e 6c 6f 6f 70 00}  //weight: 1, accuracy: High
        $x_1_2 = {62 00 00 00 ff ff ff ff 01 00 00 00 69 00 00 00 ff ff ff ff 01 00 00 00 6e 00 00 00 ff ff ff ff 01 00 00 00 2e 00 00 00 ff ff ff ff 01 00 00 00 64 00 00 00 ff ff ff ff 01 00 00 00 61 00 00 00 ff ff ff ff 01 00 00 00 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {66 81 38 4d 5a 0f 85 ?? ?? ?? ?? 33 c0}  //weight: 1, accuracy: Low
        $x_1_4 = {50 68 00 20 00 00 8b 45 ?? 8b 40 50 50 8b 45 ?? 8b 40 34 50 6a ff e8 ?? ?? ?? ?? 89 45}  //weight: 1, accuracy: Low
        $x_1_5 = {8b 00 83 78 28 00 0f 84 ?? ?? ?? ?? 33 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Dexphot_2147731153_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dexphot"
        threat_id = "2147731153"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dexphot"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".Headers['User-Agent'] = 'Windows Installer'" wide //weight: 1
        $x_1_2 = ".DownloadFile('http" wide //weight: 1
        $x_1_3 = ".info/" wide //weight: 1
        $x_1_4 = "Start-Process " wide //weight: 1
        $x_1_5 = "-ArgumentList '/q" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dexphot_H_2147731280_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dexphot.H!!Dexphot.H"
        threat_id = "2147731280"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dexphot"
        severity = "Critical"
        info = "Dexphot: an internal category used to refer to some threats"
        info = "H: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 e2 e1 a3 dd 66 89 04 24 9c 60}  //weight: 1, accuracy: High
        $x_1_2 = {68 f0 8f 5b 1e ff 34 24 e9}  //weight: 1, accuracy: High
        $x_1_3 = {68 f5 25 c2 2a 9c 52 68 2a 94 2d 48 8d 64 24 30}  //weight: 1, accuracy: High
        $x_1_4 = {60 9c 68 d6 6e 60 91 e9 ?? ?? ?? ?? e8 ?? ?? ?? ?? 0f b6 c3}  //weight: 1, accuracy: Low
        $x_10_5 = {78 55 6e 7a 72 54 00 00 ff ff ff ff 02 00 00 00 63 47 00 00 ff ff ff ff 04 00 00 00 39 33 5a 58 00 00 00 00 ff ff ff ff 03 00 00 00 4a 7a 61 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dexphot_G_2147731294_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dexphot.G!!Dexphot.G"
        threat_id = "2147731294"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dexphot"
        severity = "Critical"
        info = "Dexphot: an internal category used to refer to some threats"
        info = "G: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {e9 26 00 00 00 61 67 74 30 34 30 31 2e 64 6c 6c 00 43 72 65 61 74 65 4d 75 74 65 78 41 00 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 00 60 68}  //weight: 10, accuracy: High
        $x_3_2 = "XMRig" ascii //weight: 3
        $x_3_3 = "JC Expert Cryptonote CPU Miner" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Dexphot_CA_2147735853_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dexphot.CA"
        threat_id = "2147735853"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dexphot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 00 65 00 78 00 65 00 20 00 [0-32] 70 00 61 00 63 00 6b 00 61 00 67 00 65 00 [0-16] 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 00 65 00 78 00 65 00 22 00 20 00 [0-32] 70 00 61 00 63 00 6b 00 61 00 67 00 65 00 [0-16] 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
        $n_1_3 = "taskhostw.exe" wide //weight: -1
        $n_10_4 = "dl.tbcrelease.net/package" wide //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

rule Trojan_Win32_Dexphot_CB_2147735854_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dexphot.CB"
        threat_id = "2147735854"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dexphot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 00 65 00 78 00 65 00 20 00 [0-32] 2d 00 69 00 [0-16] 20 00 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 00 65 00 78 00 65 00 20 00 [0-32] 2f 00 69 00 [0-16] 20 00 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 00 65 00 78 00 65 00 22 00 20 00 [0-32] 2d 00 69 00 [0-16] 20 00 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
        $x_1_4 = {2e 00 65 00 78 00 65 00 22 00 20 00 [0-32] 2f 00 69 00 [0-16] 20 00 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
        $n_10_5 = "youtube-dl.exe" wide //weight: -10
        $n_10_6 = "ffmpeg.exe" wide //weight: -10
        $n_10_7 = "curl.exe" wide //weight: -10
        $n_10_8 = "vstoinstaller.exe" wide //weight: -10
        $n_10_9 = "microsoft.com" wide //weight: -10
        $n_10_10 = "/feedstation/" wide //weight: -10
        $n_10_11 = "=updateindex" wide //weight: -10
        $n_10_12 = "/iplog.php?" wide //weight: -10
        $n_10_13 = "/default.aspx?" wide //weight: -10
        $n_10_14 = "localhost" wide //weight: -10
        $n_10_15 = ".co.kr" wide //weight: -10
        $n_10_16 = ".cf/" wide //weight: -10
        $n_10_17 = "cleveraccounts.com" wide //weight: -10
        $n_10_18 = "syncfx.com" wide //weight: -10
        $n_10_19 = "pass-pdam.com" wide //weight: -10
        $n_10_20 = "screengrab.exe" wide //weight: -10
        $n_10_21 = "UpdatEngine" wide //weight: -10
        $n_10_22 = "powershell" ascii //weight: -10
        $n_10_23 = "cisco" ascii //weight: -10
        $n_10_24 = "w3wp.exe" ascii //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

rule Trojan_Win32_Dexphot_CC_2147735855_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dexphot.CC"
        threat_id = "2147735855"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dexphot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 [0-32] 70 00 61 00 63 00 6b 00 61 00 67 00 65 00 [0-16] 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dexphot_CD_2147735856_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dexphot.CD"
        threat_id = "2147735856"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dexphot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 [0-32] 2d 00 69 00 [0-16] 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
        $x_1_2 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 [0-32] 2f 00 69 00 [0-16] 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
        $n_10_3 = "www.zoom.us" ascii //weight: -10
        $n_10_4 = "powershell" ascii //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

rule Trojan_Win32_Dexphot_O_2147735857_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dexphot.O"
        threat_id = "2147735857"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dexphot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2d 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 20 00 [0-32] 20 00 3d 00 20 00 27 00 6d 00 73 00 69 00 65 00 78 00 65 00 63 00}  //weight: 10, accuracy: Low
        $x_10_2 = {53 00 74 00 61 00 72 00 74 00 2d 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 [0-32] 20 00 2d 00 41 00 72 00 67 00 75 00 6d 00 65 00 6e 00 74 00 4c 00 69 00 73 00 74 00 20 00 27 00 2f 00 69 00 20 00 68 00 74 00 74 00 70 00}  //weight: 10, accuracy: Low
        $x_1_3 = "superdomain1709.info" wide //weight: 1
        $x_1_4 = "guardname.net" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Dexphot_P_2147735858_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dexphot.P"
        threat_id = "2147735858"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dexphot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".Headers['User-Agent'] = 'Windows Installer'" wide //weight: 1
        $x_1_2 = ".DownloadFile('http" wide //weight: 1
        $x_1_3 = ".info/" wide //weight: 1
        $x_1_4 = "\\dump007.dat" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

