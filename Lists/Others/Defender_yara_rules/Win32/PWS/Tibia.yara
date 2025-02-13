rule PWS_Win32_Tibia_B_2147599926_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Tibia.B"
        threat_id = "2147599926"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "add hklm\\software\\microsoft\\windows\\currentversion\\run /v Windows /d" ascii //weight: 1
        $x_1_2 = "OpenProcess" ascii //weight: 1
        $x_1_3 = "TibiaClient" ascii //weight: 1
        $x_1_4 = "&notatka=" ascii //weight: 1
        $x_1_5 = "c:\\x.exe" ascii //weight: 1
        $x_1_6 = "&numer=" ascii //weight: 1
        $x_1_7 = "&pass=" ascii //weight: 1
        $x_1_8 = "ShellExecuteA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Tibia_C_2147599931_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Tibia.C"
        threat_id = "2147599931"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "46"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_10_2 = "add hklm\\software\\microsoft\\windows\\currentversion\\run /v orcToByloLatwe /d " ascii //weight: 10
        $x_10_3 = "tibiaclient" ascii //weight: 10
        $x_10_4 = {6a 00 6a 00 68 ?? ?? 40 00 ff 35 ?? ?? 40 00 68 ?? ?? 40 00 8d 45 cc ba 03 00 00 00 e8 ?? ?? ff ff 8b 45 cc e8 ?? ?? ff ff 50 68 ?? ?? 40 00 68 ?? ?? 40 00 6a 00 e8 ?? ?? ff ff e8 ?? ?? ff ff 33 c0 5a 59 59 64 89 10}  //weight: 10, accuracy: Low
        $x_1_5 = "C:\\WINDOWS\\system32\\Drivers\\Etc\\Hosts" ascii //weight: 1
        $x_1_6 = {68 74 74 70 3a 2f 2f [0-16] 2f 76 69 70 2f 64 6f 64 61 6a 2e 70 68 70 3f 6c 6f 67 69 6e 3d}  //weight: 1, accuracy: Low
        $x_1_7 = "&pass=" ascii //weight: 1
        $x_1_8 = "&notatka=" ascii //weight: 1
        $x_1_9 = "&numer=" ascii //weight: 1
        $x_1_10 = "c:\\x.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Tibia_I_2147602400_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Tibia.I"
        threat_id = "2147602400"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 3a 5c 70 6c 69 6b 2e 65 78 65 00 ff ff ff ff 0b 00 00 00 63 3a 5c 70 6c 69 6b 2e 65 78 65 00 43 3a 5c 68 6f 73 74 65 64 2e 65 78 65 00 00 00 ff ff ff ff 2d 00 00 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 00 00 00 ff ff ff ff 1e 00 00 00 43 3a 5c 57 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 73 79 73 74 65 6d 2e 65 78 65 00 00 ff ff ff ff 06 00 00 00 68 6f 73 74 65 64 00 00 43 3a 5c 57 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 73 79 73 74 65 6d 2e 65 78 65 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {8d 55 dc 33 c0 e8 ?? ?? ?? ?? 8b 45 dc e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? b2 01 a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? a3 ?? ?? ?? ?? ba 02 00 00 80 a1 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Tibia_J_2147602536_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Tibia.J"
        threat_id = "2147602536"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "32"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "Tibia.exe" ascii //weight: 10
        $x_10_2 = "www.tibia.stealer." ascii //weight: 10
        $x_10_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e [0-21] 63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 5c [0-21] 2e 65 78 65}  //weight: 10, accuracy: Low
        $x_1_4 = "&account=" ascii //weight: 1
        $x_1_5 = "&haslo=" ascii //weight: 1
        $x_1_6 = "&level=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Tibia_K_2147605198_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Tibia.K"
        threat_id = "2147605198"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "&notatka=" ascii //weight: 1
        $x_1_2 = "&numer=" ascii //weight: 1
        $x_1_3 = "tibiaclient" ascii //weight: 1
        $x_1_4 = "add hklm\\software\\microsoft\\windows\\currentversion\\run /v" ascii //weight: 1
        $x_1_5 = "c:\\x.exe" ascii //weight: 1
        $x_10_6 = "owntibia.com" ascii //weight: 10
        $x_10_7 = {ba 03 00 00 00 e8 ?? ?? ?? ?? 8b 45 ?? e8 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 00 e8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Tibia_L_2147605534_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Tibia.L"
        threat_id = "2147605534"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 56 83 c4 f4 8b f0 54 6a 00 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 8b 04 24 50 6a 00 68 ff 0f 1f 00 e8 ?? ?? ?? ?? 8b d8 8d 44 24 04 50 6a 04 8d 44 24 10 50 56 53 e8 ?? ?? ?? ?? 53 e8 ?? ?? ?? ?? 8b 44 24 08 83 c4 0c 5e 5b c3}  //weight: 1, accuracy: Low
        $x_1_2 = "C:\\WINDOWS\\svchost.bat" ascii //weight: 1
        $x_1_3 = "C:\\WINDOWS\\System32\\system.exe" ascii //weight: 1
        $x_1_4 = "C:\\WINDOWS\\System32\\sys.exe" ascii //weight: 1
        $x_1_5 = "TibiaClient" ascii //weight: 1
        $x_1_6 = "Tibia.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Tibia_M_2147606350_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Tibia.M"
        threat_id = "2147606350"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 54 69 62 69 61 43 6c 69 65 6e 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 26 73 70 3d 00 26 70 77 3d 00 26 70 6e 3d 00}  //weight: 1, accuracy: High
        $x_1_3 = {69 6e 30 31 2e 74 00 61 2e 63 6f 6d 00 6c 6f 67}  //weight: 1, accuracy: High
        $x_1_4 = {6d 73 6d 00 65 6e 74 56 00 72 6f 73 00 6f 77 73 00 65 72 73 00 69 6f 6e 00 74 00 6e 00 6f 66 74}  //weight: 1, accuracy: High
        $x_1_5 = "ShellExecuteExA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Tibia_N_2147606388_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Tibia.N"
        threat_id = "2147606388"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "%s\\system32\\drivers\\etc\\hosts" ascii //weight: 1
        $x_1_2 = "programfiles" ascii //weight: 1
        $x_1_3 = "%s\\Internet Explorer\\" ascii //weight: 1
        $x_1_4 = "lsass.exe" ascii //weight: 1
        $x_1_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run\\" ascii //weight: 1
        $x_1_6 = "owntibia.com" ascii //weight: 1
        $x_1_7 = ".php?login=%s&numer=%s&pass=%s&notatka=%s&serwer=%s&lvl=%d&lvlp=%d&stam=%d&helm=%d&neck=%d&back=%d&arm=%d&rhand=%d&lhand=%d&legs=%d&feet=%d&ring=%d&ammo=%d&nchar=%d&lhandc=%d&rhandc=%d&ammoc=%d" ascii //weight: 1
        $x_1_8 = "TibiaClient" ascii //weight: 1
        $x_1_9 = "ShellExecuteA" ascii //weight: 1
        $x_1_10 = "127.0.0.1       localhost" ascii //weight: 1
        $x_10_11 = {c7 44 24 10 00 00 00 00 c7 44 24 0c 08 00 00 00 c7 44 24 08 ?? 50 40 00 c7 44 24 04 b4 c2 76 00 89 04 24 e8 ?? ?? 00 00 83 ec 14 c7 44 24 10 00 00 00 00 c7 44 24 0c 1e 00 00 00 c7 44 24 08 ?? 50 40 00 c7 44 24 04 94 c2 76 00 a1 ?? ?? 40 00 89 04 24 e8 ?? ?? 00 00 83 ec 14 c7 44 24 10 00 00 00 00 c7 44 24 0c 20 00 00 00 c7 44 24 08 ?? ?? 40 00 c7 44 24 04 e8 3d 76 00 a1 ?? ?? 40 00 89 04 24 e8 ?? ?? 00 00 83 ec 14 c7 44 24 10 00 00 00 00 c7 44 24 0c 04 00 00 00 c7 44 24 08 ?? 50 40 00 c7 44 24 04 60 3b 61 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 9 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Tibia_O_2147606390_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Tibia.O"
        threat_id = "2147606390"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 43 10 c7 00 54 69 62 00 c7 04 24 ff 00 00 00 e8 ?? ?? 00 00 89 83 9c 00 00 00 c7 83 94 00 00 00 00 00 00 00 c6 00 00 c7 83 98 00 00 00 00 00 00 00 c7 04 24 ff 00 00 00 e8 ?? ?? 00 00 89 43 1c c7 04 24 84 03 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 00 6c 6c 73 2e 66 c7 40 04 70 00 8b 43 08 c7 00 6c 75 73 68 c7 40 04 2f 46 69 6c c6 40 08 00 58 5a}  //weight: 1, accuracy: High
        $x_1_3 = {8b 43 0c c7 00 74 2e 70 68 c7 40 04 70 3f 73 6c 66 c7 40 08 3d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule PWS_Win32_Tibia_P_2147606911_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Tibia.P"
        threat_id = "2147606911"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "owntibia.com/vip/dodaj.php?login=%s&numer=%s&pass=%s&notatka=%s&serwer=%s&lvl=%d&lvlp=%d&stam=%d&helm=%d&neck=%d&back=%d&arm=%d&rhand=%d&lhand=%d&legs=%d&feet=%d&ring=%d&ammo=%d&nchar=%d&lhandc=%d&rhandc=%d&ammoc=%d" ascii //weight: 1
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run\\" ascii //weight: 1
        $x_1_3 = "%s\\system32\\drivers\\etc\\hosts" ascii //weight: 1
        $x_1_4 = "127.0.0.1       localhost" ascii //weight: 1
        $x_1_5 = "TibiaClient" ascii //weight: 1
        $x_1_6 = {70 72 6f 67 72 61 6d 66 69 6c 65 73 00 25 73 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 00 6c 73 61 73 73 2e 65 78 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Tibia_Q_2147607544_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Tibia.Q"
        threat_id = "2147607544"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "48"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {b8 b4 c2 76 00 e8 ?? ?? ff ff 8d 4d ?? 8b 15 ?? ?? ?? 00 b8 94 c2 76 00 e8 ?? ?? ff ff 8b 15 ?? ?? ?? 00 b8 c8 c2 76 00 e8 ?? ?? ff ff}  //weight: 10, accuracy: Low
        $x_10_2 = "Software\\Borland\\Delphi\\Locales" ascii //weight: 10
        $x_10_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 10
        $x_10_4 = {6c 6f 67 69 6e [0-2] 2e 74 69 62 69 61 2e 63 6f 6d}  //weight: 10, accuracy: Low
        $x_1_5 = "Toolhelp32ReadProcessMemory" ascii //weight: 1
        $x_1_6 = "tibia-inject" ascii //weight: 1
        $x_1_7 = "dodaj.php?" ascii //weight: 1
        $x_1_8 = "&conf=" ascii //weight: 1
        $x_1_9 = "&acc=" ascii //weight: 1
        $x_1_10 = "&pass=" ascii //weight: 1
        $x_1_11 = "&nick=" ascii //weight: 1
        $x_1_12 = "&lvl=" ascii //weight: 1
        $x_1_13 = "Gadu-Gadu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 8 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Tibia_U_2147610191_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Tibia.U"
        threat_id = "2147610191"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 74 74 70 3a 2f 2f [0-48] 2f 76 69 70 2f 64 6f 64 61 6a 2e 70 68 70 3f}  //weight: 1, accuracy: Low
        $x_1_2 = "Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\" ascii //weight: 1
        $x_1_3 = "%s\\\\system32\\\\drivers\\\\etc\\\\hosts" ascii //weight: 1
        $x_1_4 = {31 32 37 2e 30 2e 30 2e 31 [0-16] 6c 6f 63 61 6c 68 6f 73 74}  //weight: 1, accuracy: Low
        $x_1_5 = "%s\\\\Internet Explorer\\\\" ascii //weight: 1
        $x_1_6 = "TibiaClient" ascii //weight: 1
        $x_1_7 = "lsass.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Tibia_W_2147612317_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Tibia.W"
        threat_id = "2147612317"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://tibiahack.czweb.org/adduser.php?num=" wide //weight: 1
        $x_1_2 = "&pass=" wide //weight: 1
        $x_1_3 = "Ultimate Tibia Hack" ascii //weight: 1
        $x_1_4 = "\\YPKISS~1\\ULTIMA~1\\ULTIMA~1.VBP" wide //weight: 1
        $x_1_5 = "SERVER MESSAGE: Bad password or account number. Try again." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Tibia_X_2147612319_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Tibia.X"
        threat_id = "2147612319"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {80 3c 03 2e 0f 94 c0 0f b6 c0 01 45 d0 43 39 fb 72 eb}  //weight: 2, accuracy: High
        $x_2_2 = {80 38 7c 0f 85 f0 02 00 00 c6 00 00 c7 05 ?? ?? 40 00 00 00 00 00 83 3d ?? ?? 40 00 02 0f 8f 9c 00 00 00}  //weight: 2, accuracy: Low
        $x_2_3 = {80 3c 10 7c 75 0c ff 05 ?? ?? 40 00 80 3c 10 7c [0-2] 83 3d ?? ?? 40 00 01 a1 ?? ?? 40 00 83 d0 00 a3 ?? ?? 40 00 83 3d ?? ?? 40 00 01 0f 94 c0 0f b6 c0 03 05 ?? ?? 40 00 a3 ?? ?? 40 00 ff 05 ?? ?? 40 00 3b 0d ?? ?? 40 00 7f af}  //weight: 2, accuracy: Low
        $x_2_4 = "owntibia.com" ascii //weight: 2
        $x_1_5 = "194.181.6.133" ascii //weight: 1
        $x_1_6 = "TIBIA_SUX/666.0" ascii //weight: 1
        $x_1_7 = "105.117.98.119.123.37.101.125.104" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Tibia_Y_2147612641_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Tibia.Y"
        threat_id = "2147612641"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {79 73 69 6f 6c 6f 67 67 65 72 2e 79 6f 79 6f 2e 70 6c 2f 61 64 64 72 65 73 73 74 69 62 69 61 2e 74 78 74 00 ff ff ff ff 2c 00 00 00 68 74 74 70 3a 2f 2f 77 77 77 2e 72 79 73 69 6f 6c 6f 67 67 65 72 2e 79 6f 79 6f 2e 70 6c 2f 69 74 65 6d 74 69 62 69 61 2e 74 78 74 00 00 00 00 ff ff ff ff 2a 00 00 00 68 74 74 70 3a 2f 2f 77 77 77 2e 72 79 73 69 6f 6c 6f 67 67 65 72 2e 79 6f 79 6f 2e 70 6c 2f 69 64 74 69 62 69 61 2e 74 78 74 00 00 ff ff ff ff 25 00 00 00 68 74 74 70 3a 2f 2f 77 77 77 2e 72 79 73 69 6f 6c 6f 67 67 65 72 2e 79 6f 79 6f 2e 70 6c 2f 67 67 2e 74 78 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "TibiaClient" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Tibia_V_2147616875_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Tibia.gen!V"
        threat_id = "2147616875"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibia"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c7 44 24 08 01 00 00 00 c7 44 24 04 ?? ?? ?? ?? c7 04 24 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 ec 0c e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? c7 04 24 88 13 00 00 e8 ?? ?? ?? ?? 83 ec 04 eb ea}  //weight: 10, accuracy: Low
        $x_1_2 = "Fgyttfrj" ascii //weight: 1
        $x_1_3 = "tkohqi" ascii //weight: 1
        $x_1_4 = "FGGvide" ascii //weight: 1
        $x_1_5 = "mtpkzXmklegv" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Tibia_AB_2147617428_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Tibia.AB"
        threat_id = "2147617428"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "42"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "?login=" ascii //weight: 1
        $x_1_2 = "&pass" ascii //weight: 1
        $x_1_3 = {70 61 73 73 77 6f 72 64 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 75 73 65 72 6e 61 6d 65 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 50 61 73 73 77 6f 72 64 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 55 73 65 72 6e 61 6d 65 00}  //weight: 1, accuracy: Low
        $x_10_4 = "tibia" ascii //weight: 10
        $x_10_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 10
        $x_10_6 = "ReadProcessMemory" ascii //weight: 10
        $x_10_7 = {ff 0f 1f 00 e8 04 00 50 6a 00 68}  //weight: 10, accuracy: Low
        $n_10_8 = {53 6f 66 74 77 61 72 65 5c 57 69 73 65 54 6f 70 5c 47 47 4c 6f 67 69 6e 43 6c 69 65 6e 74 00}  //weight: -10, accuracy: High
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((4 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Tibia_AC_2147617429_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Tibia.AC"
        threat_id = "2147617429"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {05 8d 34 b6 81 c6 ?? ?? 62 00 16 00 b8 ?? ?? 62 00 e8 ?? ?? ff ff 88 04 24 ?? ?? 0f b6 c3 8b f0 c1 e6}  //weight: 10, accuracy: Low
        $x_10_2 = {ff 0f 1f 00 e8 04 00 50 6a 00 68}  //weight: 10, accuracy: Low
        $x_3_3 = {7e 27 be 01 00 00 00 8d 45 f4 8b 55 fc 0f b6 54 32 ff 83 ea 03 e8 ?? ?? ?? ff 8b 55 f4 8d 45 f8 e8 ?? ?? ?? ff 46 4b 75 de}  //weight: 3, accuracy: Low
        $x_1_4 = "ReadProcessMemory" ascii //weight: 1
        $x_1_5 = "OpenProcess" ascii //weight: 1
        $x_1_6 = "GetWindowThreadProcessId" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Tibia_AG_2147621851_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Tibia.AG"
        threat_id = "2147621851"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 08 80 3c 03 2e 0f 94 c0 0f b6 c0 01 45 ?? 43 39 fb 72 eb 8b 45 ?? 83 c0 02}  //weight: 1, accuracy: Low
        $x_1_2 = {81 ec dc 01 00 00 8b 5d 08 89 1c 24 ff 93 60 06 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Tibia_AH_2147622319_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Tibia.AH"
        threat_id = "2147622319"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {68 74 74 70 3a 2f 2f 74 69 62 69 61 2d 69 6e 6a 65 63 74 2e 63 6f 6d 2f [0-8] 2e 70 68 70}  //weight: 10, accuracy: Low
        $x_10_2 = "login01.tibia.com" ascii //weight: 10
        $x_10_3 = "/c attrib +s +h" ascii //weight: 10
        $x_1_4 = "infname=" ascii //weight: 1
        $x_1_5 = "&infid=" ascii //weight: 1
        $x_1_6 = "&pass=" ascii //weight: 1
        $x_1_7 = "&acc=" ascii //weight: 1
        $x_1_8 = "&nick=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Tibia_AI_2147623606_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Tibia.AI"
        threat_id = "2147623606"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 d2 8a 54 1f ff 03 d3 f7 d2 88 54 18 ff 43 4e 75 e7}  //weight: 1, accuracy: High
        $x_1_2 = {8b d8 6b c6 54 03 d8 8b d7 8d 03 e8}  //weight: 1, accuracy: High
        $x_1_3 = {26 70 61 73 73 3d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Tibia_AK_2147624306_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Tibia.AK"
        threat_id = "2147624306"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2d 81 00 00 00 73 02 31 c0 6a 00 6a 00 50 ff 36 e8 ?? ?? ff ff 40 0f 84 ca 00 00 00 6a 00 89 e2 6a 00 52 68 80 00 00 00}  //weight: 5, accuracy: Low
        $x_2_2 = {54 69 62 69 61 43 6c 69 65 6e 74 00}  //weight: 2, accuracy: High
        $x_1_3 = {3f 6e 6f 74 65 3d [0-16] 26 61 63 63 3d [0-16] 26 70 61 73 73 3d}  //weight: 1, accuracy: Low
        $x_1_4 = {26 73 65 6c 63 68 61 72 3d [0-16] 26 73 65 6c 73 65 72 76 3d [0-16] 26 73 65 6c 6c 76 6c 3d}  //weight: 1, accuracy: Low
        $x_1_5 = {75 73 65 72 3d [0-16] 26 67 61 6d 65 3d 74 69 62 69 61}  //weight: 1, accuracy: Low
        $x_2_6 = {7c 08 81 fe ?? ?? 00 00 7e 0a 0f b6 03 e8 ?? ?? ?? ?? 88 03 46 43 81 fe ?? ?? 00 00 75 dc}  //weight: 2, accuracy: Low
        $x_1_7 = {0f b6 c0 2d ?? ?? 00 00 85 c0 7d 09 05 ?? ?? 00 00 85 c0 7c f7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Tibia_AL_2147626060_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Tibia.AL"
        threat_id = "2147626060"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {c7 44 0b ff 26 76 3d 31 66 c7 44 18 04 2e 31 c6 44 18 06 00 89 1c 24}  //weight: 2, accuracy: High
        $x_2_2 = "Host: OWNTIBIA.COM" ascii //weight: 2
        $x_1_3 = "POST /vip/dodaj.php" ascii //weight: 1
        $x_1_4 = {75 73 65 72 5f 69 6e 66 6f 3d 00 26 61 63 63 5f 69 6e 66 6f 3d 00 26 63 68 61 72 5f 6c 69 73 74 3d 00 26 65 71 5f 6c 69 73 74 3d 00}  //weight: 1, accuracy: High
        $x_1_5 = {54 69 62 69 61 43 6c 69 65 6e 74 00}  //weight: 1, accuracy: High
        $x_1_6 = {6c 73 61 73 73 2e 65 78 65 00 36 35 00 72 75 6e 61 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Tibia_AM_2147627838_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Tibia.AM"
        threat_id = "2147627838"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VRIWZDUH_Plfurvriw_Zlqgrzv_FxuuhqwYhuvlrq_Uxq" ascii //weight: 1
        $x_1_2 = ")dffrxqwqdph@" ascii //weight: 1
        $x_1_3 = ")fkdudfwhu@" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Tibia_AQ_2147630199_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Tibia.AQ"
        threat_id = "2147630199"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {74 69 62 69 61 63 6c 69 65 6e 74 [0-16] 41 63 63 6f 75 6e 74 3a [0-16] 50 61 73 73 77 6f 72 64 3a}  //weight: 10, accuracy: Low
        $x_10_2 = {53 56 83 c4 f4 8b f0 54 6a 00 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 8b 04 24 50 6a 00 68 ff 0f 1f 00 e8 ?? ?? ?? ?? 8b d8 8d 44 24 04 50 6a 04 8d 44 24 10 50 56 53 e8 ?? ?? ?? ?? 53 e8 ?? ?? ?? ?? 8b 44 24 08 83 c4 0c 5e 5b c3}  //weight: 10, accuracy: Low
        $x_1_3 = "readprocessmemory" ascii //weight: 1
        $x_1_4 = "getwindowthreadprocessid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Tibia_AR_2147630777_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Tibia.AR"
        threat_id = "2147630777"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 8a 54 1f ff 03 d3 f7 d2 88 54 18 ff 43 4e 75 e7}  //weight: 1, accuracy: High
        $x_1_2 = {54 69 62 69 61 43 6c 69 65 6e 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {8b 45 f8 50 6a 00 68 ff 0f 1f 00 e8 ?? ?? ?? ?? 8d 55 fc 52 68 ff 00 00 00 8d 95 f9 fe ff ff 52 53 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Tibia_AS_2147631201_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Tibia.AS"
        threat_id = "2147631201"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 69 62 69 61 63 6c 69 65 6e 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {63 3a 5c 66 76 72 33 32 2e 63 6f 6d 00}  //weight: 1, accuracy: High
        $x_1_3 = {33 d2 8a 54 1f ff 03 d3 f7 d2 88 54 18 ff 43 4e 75 e7}  //weight: 1, accuracy: High
        $x_1_4 = {b3 ff 8d b5 ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? 8a 16 e8 ?? ?? ?? ?? 8b 95 ?? ?? ?? ?? 8b c7 e8 ?? ?? ?? ?? 46 fe cb 75 e1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule PWS_Win32_Tibia_AT_2147631968_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Tibia.AT"
        threat_id = "2147631968"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {80 38 37 75 11 14 00 c7 00 ?? 00 00 00 8b c3 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 03}  //weight: 3, accuracy: Low
        $x_3_2 = {0f b6 44 10 ff 88 03 ff 45 f4 43 4e 75 d0}  //weight: 3, accuracy: High
        $x_1_3 = "GET /newr.php?" wide //weight: 1
        $x_1_4 = "Host: wartibia.com" wide //weight: 1
        $x_1_5 = {2d 00 78 00 31 00 33 00 [0-4] 25 00 64 00}  //weight: 1, accuracy: Low
        $x_1_6 = "87.98.141.130" ascii //weight: 1
        $x_1_7 = "tbi_readed_data" ascii //weight: 1
        $x_1_8 = "tbi_data" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 6 of ($x_1_*))) or
            ((2 of ($x_3_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Tibia_AV_2147633339_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Tibia.AV"
        threat_id = "2147633339"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "step=checkemail&key1=" wide //weight: 2
        $x_1_2 = "wt_guard" wide //weight: 1
        $x_1_3 = "character_eqlist" ascii //weight: 1
        $x_2_4 = "tbi_readed_data" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Tibia_AW_2147635789_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Tibia.AW"
        threat_id = "2147635789"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c net stop SharedAccess" wide //weight: 1
        $x_1_2 = "login01.tibia.com" wide //weight: 1
        $x_2_3 = "Security Center" wide //weight: 2
        $x_2_4 = "Tibia Account Hacked" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Tibia_AX_2147636235_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Tibia.AX"
        threat_id = "2147636235"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {be 1e 00 00 00 8d 45 ?? 50 56 8d 85 ?? ?? ?? ?? 50 68 e4 d3 77 00 53 e8}  //weight: 2, accuracy: Low
        $x_1_2 = "tibiaClient" ascii //weight: 1
        $x_1_3 = "smtp.serwer.pl" ascii //weight: 1
        $x_3_4 = "keyloggervsk3" ascii //weight: 3
        $x_1_5 = "IdSMTP1Connected" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Tibia_AY_2147637390_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Tibia.AY"
        threat_id = "2147637390"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "52"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 2e 30 2e 30 2e 30 20 [0-6] 74 69 62 69 61 2e 63 6f 6d}  //weight: 1, accuracy: Low
        $x_1_2 = {30 2e 30 2e 30 2e 30 20 [0-6] 6a 6f 79 6d 61 78 2e 63 6f 6d}  //weight: 1, accuracy: Low
        $x_1_3 = {30 2e 30 2e 30 2e 30 20 [0-6] 6d 65 74 69 6e 32 2e 70 6c}  //weight: 1, accuracy: Low
        $x_1_4 = {30 2e 30 2e 30 2e 30 20 [0-9] 77 65 62 7a 65 6e 2e 6e 65 74}  //weight: 1, accuracy: Low
        $x_1_5 = {30 2e 30 2e 30 2e 30 20 [0-6] 74 68 65 63 72 69 6d 73 2e 63 6f 6d}  //weight: 1, accuracy: Low
        $x_1_6 = {30 2e 30 2e 30 2e 30 20 [0-6] 6d 61 72 67 6f 6e 65 6d 2e 70 6c}  //weight: 1, accuracy: Low
        $x_10_7 = "POST /_Common/procLogin.aspx" ascii //weight: 10
        $x_10_8 = "TibiaClient" ascii //weight: 10
        $x_10_9 = "Tibia - Free Multiplayer Online Role Playing Game - Account" ascii //weight: 10
        $x_10_10 = "SRO_Client" ascii //weight: 10
        $x_10_11 = "hackshield\\hsupdate.exe" ascii //weight: 10
        $x_10_12 = "&game=tibia&acc=" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 2 of ($x_1_*))) or
            ((6 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Tibia_AZ_2147640130_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Tibia.AZ"
        threat_id = "2147640130"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "TibiaClient" ascii //weight: 2
        $x_3_2 = "c:\\plik.exe" ascii //weight: 3
        $x_1_3 = "InternalGetWindowText" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Tibia_BD_2147642453_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Tibia.BD"
        threat_id = "2147642453"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_6_1 = "infector_id" ascii //weight: 6
        $x_3_2 = "ttbi_data" ascii //weight: 3
        $x_2_3 = "skill_points_fishing" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Tibia_BF_2147646232_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Tibia.BF"
        threat_id = "2147646232"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 62 69 5f 72 65 61 64 65 64 5f 64 61 74 61 28 00}  //weight: 1, accuracy: High
        $x_1_2 = {74 62 69 5f 64 61 74 61 30 00}  //weight: 1, accuracy: High
        $x_1_3 = {38 37 2e 39 38 2e 31 34 31 2e 31 33 30 00}  //weight: 1, accuracy: High
        $x_1_4 = "[DEBUG]" wide //weight: 1
        $x_1_5 = {ff 0f 1f 00 e8 04 00 50 6a 00 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Tibia_BH_2147646562_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Tibia.BH"
        threat_id = "2147646562"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2d 81 00 00 00 73 02 31 c0 6a 00 6a 00 50 ff 36 e8 ?? ?? ff ff 40 0f 84 ca 00 00 00 6a 00 89 e2 6a 00 52 68 80 00 00 00}  //weight: 5, accuracy: Low
        $x_5_2 = "Tibia_rkey" ascii //weight: 5
        $x_1_3 = "&password=" wide //weight: 1
        $x_1_4 = "/add_data.php?reckey=" wide //weight: 1
        $x_1_5 = "wow_dir=" wide //weight: 1
        $x_1_6 = "metin2.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Tibia_BI_2147647305_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Tibia.BI"
        threat_id = "2147647305"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {ff 0f 1f 00 e8 04 00 50 6a 00 68}  //weight: 5, accuracy: Low
        $x_2_2 = "TibiaClient" wide //weight: 2
        $x_1_3 = ".php?in=" wide //weight: 1
        $x_1_4 = {55 00 73 00 65 00 72 00 73 00 5c 00 [0-16] 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00}  //weight: 1, accuracy: Low
        $x_1_5 = {47 00 65 00 74 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 49 00 6e 00 66 00 6f 00 [0-16] 4b 00 45 00 52 00 4e 00 45 00 4c 00 33 00 32 00 2e 00 44 00 4c 00 4c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Tibia_BJ_2147648063_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Tibia.BJ"
        threat_id = "2147648063"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = ":ttibia.:1(" ascii //weight: 2
        $x_1_2 = "account_name" ascii //weight: 1
        $x_1_3 = "account_password" ascii //weight: 1
        $x_2_4 = {53 6a 00 6a 09 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? a3 ?? ?? ?? ?? 83 3d ?? ?? ?? ?? 00 0f 95 c3 84 db 74 ?? 68 ?? ?? ?? ?? a1 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? a1 c0 22 4b 00 50 6a 00 68 ff 0f 1f 00 e8 ?? ?? ?? ?? a3 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b c3 5b c3}  //weight: 2, accuracy: Low
        $x_2_5 = {ba 03 00 00 00 e8 ?? ?? ?? ?? 8d 45 fc ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 fc 80 38 30 75 ?? 6a 0a e8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Tibia_BN_2147650876_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Tibia.BN"
        threat_id = "2147650876"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {31 3d 00 00 74 69 62 69 61 2e 63 6f 6d 00 00 00 61 70 70 64}  //weight: 5, accuracy: High
        $x_2_2 = "\\vmreg.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Tibia_BP_2147651416_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Tibia.BP"
        threat_id = "2147651416"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TibiaClient" wide //weight: 1
        $x_2_2 = "wostock.exel.txtopend.bat" wide //weight: 2
        $x_1_3 = "kf=kernel32.dll" wide //weight: 1
        $x_2_4 = "ow=,ii=,iv=,cc=,tv=,dt=an=,ap=,ci=,cn=,cl=,ce=,ps=account" wide //weight: 2
        $x_2_5 = ":labahdel \"\"if EXIST \"\" goto labah" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Tibia_BR_2147652814_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Tibia.BR"
        threat_id = "2147652814"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 54 69 62 69 61 43 6c 69 65 6e 74 00}  //weight: 1, accuracy: High
        $x_1_2 = "account/?subtopic=" ascii //weight: 1
        $x_10_3 = "software\\microsoft\\windows\\currentversion\\run" ascii //weight: 10
        $x_1_4 = {26 6c 6f 67 69 6e 70 61 73 73 77 6f 72 64 3d 00}  //weight: 1, accuracy: High
        $x_1_5 = {80 3c 2b 43 0f 85 ?? ?? ?? ?? 80 7c 2b 01 68 0f 85 ?? ?? ?? ?? 80 7c 2b 02 61 0f 85 ?? ?? ?? ?? 80 7c 2b 03 72 0f 85 ?? ?? ?? 80 7c 2b 04 61}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Tibia_BT_2147656282_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Tibia.BT"
        threat_id = "2147656282"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ews2_32.dll" wide //weight: 1
        $x_1_2 = "&identyfikator=" ascii //weight: 1
        $x_1_3 = "baza=" ascii //weight: 1
        $x_1_4 = "&wersja=" ascii //weight: 1
        $x_1_5 = "&wer_sys=" ascii //weight: 1
        $x_1_6 = "&acc=" ascii //weight: 1
        $x_1_7 = "&pass=" ascii //weight: 1
        $x_1_8 = "&nick=" ascii //weight: 1
        $x_1_9 = "&helmet=" ascii //weight: 1
        $x_1_10 = "&backpack=" ascii //weight: 1
        $x_1_11 = "&amulet=" ascii //weight: 1
        $x_1_12 = "&bron=" ascii //weight: 1
        $x_1_13 = "&armor=" ascii //weight: 1
        $x_1_14 = "&tarcza=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Tibia_BU_2147657465_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Tibia.BU"
        threat_id = "2147657465"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "GET /place_inf2.php" ascii //weight: 1
        $x_1_2 = "Znaleziono tibie PID - %d" ascii //weight: 1
        $x_1_3 = {26 70 61 63 63 3d [0-16] 26 63 68 61 72 3d [0-16] 26 6e 6f 74 65 3d}  //weight: 1, accuracy: Low
        $x_1_4 = "\\informatyka\\rootkit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Tibia_BX_2147659355_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Tibia.BX"
        threat_id = "2147659355"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "103"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "tibiakeylogger" ascii //weight: 100
        $x_1_2 = "&identyfikator=" ascii //weight: 1
        $x_1_3 = "&acc=" ascii //weight: 1
        $x_1_4 = "&pass=" ascii //weight: 1
        $x_1_5 = "tibiainject.pl" ascii //weight: 1
        $x_1_6 = "dodaj.php?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Tibia_BY_2147659629_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Tibia.BY"
        threat_id = "2147659629"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {47 45 54 20 2f 75 ?? ?? 2e 70 68 70 3f 64 61 74 61 3d 00 26 73 69 64 3d 00 20 48 54 54 50 2f 31 2e 31 0d 0a 00 48 6f 73 74 3a 20 77 77 77 2e 75 61 6e 65 73 6b 65 79 6c 6f 67 67 65 72 2e 70 6c}  //weight: 10, accuracy: Low
        $x_3_2 = {89 4c 24 10 c7 44 24 0c 01 00 00 00 c7 44 24 08 00 00 00 00 c7 44 24 04 07 00 00 00 c7 04 24 00 00 00 00 c7 85 a8 fd ff ff ff ff ff ff e8}  //weight: 3, accuracy: High
        $x_3_3 = "\\Windows\\CurrentVersion\\Run" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Tibia_CA_2147661623_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Tibia.CA"
        threat_id = "2147661623"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {54 69 62 69 61 43 6c 69 65 6e 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {26 63 68 65 63 6b 3d 00 26 70 6f 73 3d 00}  //weight: 1, accuracy: High
        $x_1_3 = {26 70 61 73 73 77 6f 72 64 3d [0-5] 26 6c 6f 67 69 6e 3d [0-5] 26 69 64 3d}  //weight: 1, accuracy: Low
        $x_1_4 = "nighttibia.xaa.pl" ascii //weight: 1
        $x_1_5 = "NightMAREK\\Moje dokumenty\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

