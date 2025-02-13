rule Backdoor_Win32_Mdmbot_A_2147601718_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Mdmbot.A"
        threat_id = "2147601718"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Mdmbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 65 64 40 62 6c 75 2e 63 6f 6d 00 5b 53 43 41 0d f1 ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {4e 5d 3a 20 53 63 61 6e 20 6e 6f 74 20 61 63 74 69 76 65 2e 72 da b6 b5 87 37 43 75 72 64 6e 34 49 50 16 25 73}  //weight: 1, accuracy: High
        $x_1_3 = {74 74 70 3a 2f 2f 64 62 73 7e 5c 16 73 30 5a 1b 76}  //weight: 1, accuracy: High
        $x_1_4 = {6d 64 6d 2e 65 db 6d 0d b4 78 f8 5c b4 b2 64 6f 77 34 58 50 0d 5f bb fd 20 28 53 50 30}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Mdmbot_B_2147602747_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Mdmbot.B"
        threat_id = "2147602747"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Mdmbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {52 61 73 6d 6f 6e 2e 64 6c 6c 00 53 65 72 76 69 63 65 4d 61 69 6e}  //weight: 2, accuracy: High
        $x_1_2 = "VedioDriver.dll" ascii //weight: 1
        $x_1_3 = "\\mdm.exe" ascii //weight: 1
        $x_1_4 = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0" ascii //weight: 1
        $x_1_5 = "Software\\Sun\\1.1.2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Mdmbot_C_2147630925_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Mdmbot.C"
        threat_id = "2147630925"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Mdmbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 53 44 53 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 3a 5c [0-32] 41 75 72 6f 72 61 56 4e 43 5c 56 65 64 69 6f 44 72 69 76 65 72 5c [0-16] 5c 56 65 64 69 6f 44 72 69 76 65 72 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_2 = {52 53 44 53 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 3a 5c [0-32] 41 75 72 6f 72 61 56 4e 43 5c 41 76 63 5c [0-16] 5c 41 56 43 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Backdoor_Win32_Mdmbot_D_2147630926_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Mdmbot.D"
        threat_id = "2147630926"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Mdmbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rundll32.exe \"%s\", Launch" wide //weight: 1
        $x_1_2 = "%s\\%d.bak" wide //weight: 1
        $x_1_3 = {53 00 74 00 75 00 62 00 50 00 61 00 74 00 68 00 00 00 00 00 5c 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: High
        $x_1_4 = "I am running under mcproxy.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win32_Mdmbot_F_2147658044_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Mdmbot.F"
        threat_id = "2147658044"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Mdmbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "svchost.exe -k netsvcs" wide //weight: 1
        $x_1_2 = "Microsoft\\Windows NT\\CurrentVersion\\Svchost" wide //weight: 1
        $x_1_3 = "Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_4 = "rundll32.exe \"%s\", Launch" wide //weight: 1
        $x_1_5 = "WinSta0\\Default" wide //weight: 1
        $x_1_6 = "McpRoXy" wide //weight: 1
        $x_1_7 = "rat_UnInstall" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Backdoor_Win32_Mdmbot_G_2147692129_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Mdmbot.G!dha"
        threat_id = "2147692129"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Mdmbot"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {25 00 54 00 45 00 4d 00 50 00 25 00 5c 00 75 00 69 00 64 00 2e 00 61 00 78 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {25 00 25 00 54 00 45 00 4d 00 50 00 25 00 25 00 5c 00 25 00 73 00 5f 00 70 00 2e 00 61 00 78 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {8d 8c 3e 10 02 00 00 8a 14 3e 8a 1c 01 32 da 88 1c 01 8b 54 3e 04 40 3b c2 72 ec}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Mdmbot_H_2147707264_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Mdmbot.H!dll!dha"
        threat_id = "2147707264"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Mdmbot"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cache.dnsde.com" wide //weight: 1
        $x_1_2 = "__rat_UnInstall__%d" wide //weight: 1
        $x_1_3 = "NeverSayDie!" ascii //weight: 1
        $x_1_4 = "%%TEMP%%\\%s_p.ax" wide //weight: 1
        $x_1_5 = "http://%ls:%d/l%x" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win32_Mdmbot_G_2147707265_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Mdmbot.G!loader!dha"
        threat_id = "2147707265"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Mdmbot"
        severity = "Critical"
        info = "loader: an internal category used to refer to some threats"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {68 01 00 00 80 ff 15 ?? ?? ?? ?? 8d 54 24 08 52 ff 15 ?? ?? ?? ?? 8b 4c 24 00 50 8d 44 24 0c 50 6a 01 6a 00 68 ?? ?? ?? ?? 51 ff 15 ?? ?? ?? 00 8b 54 24 00 52 ff 15 ?? ?? ?? ?? 8d 44 24 08 6a 05 50 ff 15}  //weight: 5, accuracy: Low
        $x_1_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 41 63 74 69 76 65 20 53 65 74 75 70 5c 49 6e 73 74 61 6c 6c 65 64 20 43 6f 6d 70 6f 6e 65 6e 74 73 5c 7b ?? ?? ?? ?? ?? ?? ?? ?? 2d ?? ?? ?? ?? 2d ?? ?? ?? ?? 2d ?? ?? ?? ?? 2d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 7d}  //weight: 1, accuracy: Low
        $x_1_3 = {22 00 25 00 73 00 22 00 20 00 2f 00 49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 00 00 00 00 00 00 63 00 74 00 66 00 6d 00 6f 00 6d 00}  //weight: 1, accuracy: High
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_5_5 = "C:\\Documents and Settings\\Administrator\\Aliapp.exe" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

