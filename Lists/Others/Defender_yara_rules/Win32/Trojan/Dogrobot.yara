rule Trojan_Win32_Dogrobot_A_2147601391_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dogrobot.gen!A"
        threat_id = "2147601391"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dogrobot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\Device\\Harddisk0\\DR0" ascii //weight: 1
        $x_1_2 = "\\\\.\\PhysicalDrive0" ascii //weight: 1
        $x_5_3 = {b8 ff ff ff ff 0b db 74 15 8a 13 32 d0 0f b6 d2 c1 e8 08 33 04 95 ?? ?? ?? ?? 43 49 75 eb f7 d0 c3}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Dogrobot_B_2147601392_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dogrobot.gen!B"
        threat_id = "2147601392"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dogrobot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\PhysicalDrive%d" wide //weight: 1
        $x_1_2 = "\\Device\\SEDISK" wide //weight: 1
        $x_5_3 = {8b 75 0c 8b 46 60 81 78 0c 04 28 40 9c 57 89 4d fc 74 1a}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Dogrobot_C_2147604869_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dogrobot.gen!C"
        threat_id = "2147604869"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dogrobot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 7d 0c 09 76 19 83 7d 0c 14 73 13 66 c7 45 ?? 31 00 0f b7 45 0c 83 c0 26 66 89 45 ?? eb 2a 83 7d 0c 13 76 19 83 7d 0c 1e 73 13 66 c7 45 ?? 32 00 0f b7 45 0c 83 c0 1c 66 89 45 ?? eb 0b 0f b7 45 0c 83 c0 30 66 89 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dogrobot_D_2147604933_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dogrobot.gen!D"
        threat_id = "2147604933"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dogrobot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 4d 44 20 4f 6e 65 0a}  //weight: 1, accuracy: High
        $x_1_2 = {43 72 61 63 6b 4d 65 2e 73 79 73 00}  //weight: 1, accuracy: High
        $x_1_3 = "dwNeededSize 2: %d" ascii //weight: 1
        $x_1_4 = {74 30 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dogrobot_E_2147605324_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dogrobot.gen!E"
        threat_id = "2147605324"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dogrobot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {be 8b ff 55 8b 39 30 75 16 81 78 04 ec 5d ff 25 75 0d 8b 50 08 8b 0a}  //weight: 1, accuracy: High
        $x_1_2 = {66 81 38 ff 25 89 45 d0 c6 45 ff 01 74 06 c6 45 ff 00 eb 0b}  //weight: 1, accuracy: High
        $x_1_3 = {81 78 0c 04 3c 00 f0 0f 85}  //weight: 1, accuracy: High
        $x_1_4 = "CLASSPNP.SYS" ascii //weight: 1
        $x_1_5 = "\\Device\\Harddisk0\\DR0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Dogrobot_H_2147605360_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dogrobot.gen!H"
        threat_id = "2147605360"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dogrobot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7e 30 0f be 34 1f 83 fe 20 7c 22 83 fe 7e 7f 1d e8 ?? ?? ?? ?? 8d 04 40 b9 5f 00 00 00 c1 e0 05 8d 44 30 e0 99 f7 f9 80 c2 20 88 14 1f 47 3b fd 7c d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dogrobot_I_2147608067_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dogrobot.gen!I"
        threat_id = "2147608067"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dogrobot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 48 30 8b 81 b0 00 00 00 8b 81 a8 00 00 00 33 db 8b 99 a4 00 00 00 83 fb 05 75 6c 0b c0 75 20 c7 05 ?? ?? ?? ?? 6f 00 00 00 c7 05 ?? ?? ?? ?? e1 00 00 00 c7 05 ?? ?? ?? ?? 18 00 00 00 eb 48 83 f8 01 75 20}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 45 d0 4b 65 53 65 c7 45 d4 72 76 69 63 c7 45 d8 65 44 65 73 c7 45 dc 63 72 69 70 c7 45 e0 74 6f 72 54 c7 45 e4 61 62 6c 65 c7 45 e8 00 00 00 00 8d 45 d0 50 ff 75 f0 e8}  //weight: 1, accuracy: High
        $x_1_3 = {81 3c 31 2e 72 73 72 75 33 83 7c 31 04 63 75 2c 8b 44 31 0c 89 45 8c 8b 44 31 14 89 45 88 8b 44 31 24 3d 60 00 00 e0 75 09}  //weight: 1, accuracy: High
        $x_1_4 = {c7 85 80 fe ff ff 5c 5c 2e 5c c7 85 84 fe ff ff 50 68 79 73 c7 85 88 fe ff ff 69 63 61 6c c7 85 8c fe ff ff 44 72 69 76 c7 85 90 fe ff ff 65 30 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {8b 08 36 8a 5c 2e 08 02 d9 02 da 46 0f b6 d3 83 fe 04 8b 1c 97 89 18 89 0c 97 7c 02 33 f6 83 c0 04 ff 4d 0c 75 da}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Dogrobot_A_2147611563_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dogrobot.A"
        threat_id = "2147611563"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dogrobot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 4c 82 fc 8b 0d ?? ?? ?? ?? 3b c1 7c e2 a1 ?? ?? ?? ?? 0f 22 c0 fb c3}  //weight: 2, accuracy: Low
        $x_2_2 = {66 c7 45 fc e3 03 66 89 45 f8 66 89 45 fa ff 5d f8 8b c4 8b 64 24 04}  //weight: 2, accuracy: High
        $x_2_3 = {6a 08 52 6a 26 ff 15 ?? ?? ?? ?? 85 c0 7c 16 e8 ?? ?? 00 00 85 c0 74 0d 68 ?? ?? ?? ?? e8 ?? 00 00 00}  //weight: 2, accuracy: Low
        $x_1_4 = {00 74 61 73 6b 6b 69 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_5 = "/f /im avp.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Dogrobot_J_2147617114_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dogrobot.gen!J"
        threat_id = "2147617114"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dogrobot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {c6 45 f0 e9 8b 45 14 8b 5d 08 2b c3 83 e8 05 89 45 f1 8d 45 f0 6a 05}  //weight: 2, accuracy: High
        $x_2_2 = {8a 0c 32 8a c2 2c 21 8b fe d0 e0 02 c8 33 c0 88 0c 32 83 c9 ff 42 f2 ae f7 d1 49 3b d1 72 e1}  //weight: 2, accuracy: High
        $x_1_3 = {81 e5 00 f0 00 00 81 fd 00 30 00 00 75 31 8b 5c 24 10 8b 6c 24 28 43 25 ff 0f 00 00 89 5c 24 10 8b 19 03 c3 8b 1c 30 2b 5d 1c 8b 6c 24 2c 3b dd 75 09 66 81 7c 30 fe c7 05 74 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Dogrobot_B_2147617561_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dogrobot.B"
        threat_id = "2147617561"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dogrobot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 e1 03 50 68 10 30 00 10 6a 67 f3 a4 e8 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = "\\drivers\\RESSDT.sys" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dogrobot_D_2147618038_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dogrobot.D"
        threat_id = "2147618038"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dogrobot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd /c cacls \"%s\" /e /p everyone:f" ascii //weight: 1
        $x_1_2 = "if exist \"%s\" goto " ascii //weight: 1
        $x_1_3 = "KeServiceDescriptorTable" ascii //weight: 1
        $x_1_4 = "360tray.exe" ascii //weight: 1
        $x_1_5 = "\\update.dll" ascii //weight: 1
        $x_1_6 = "rundll32.exe %s, drop" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dogrobot_E_2147618535_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dogrobot.E"
        threat_id = "2147618535"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dogrobot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 6d 64 20 2f 63 20 74 61 73 6b 6b 69 6c 6c 20 2f 69 6d 20 (65 6b|53 63 61 6e 46) 2e 65 78 65 20 2f 66}  //weight: 1, accuracy: Low
        $x_1_2 = {63 6d 64 20 2f 63 20 73 63 20 63 6f 6e 66 69 67 20 (65 6b|61) 20 73 74 61 72 74 3d 20 64 69 73 61 62 6c 65 64}  //weight: 1, accuracy: Low
        $x_1_3 = "cmd /c cacls \"%s\" /e /p everyone:f" ascii //weight: 1
        $x_1_4 = {83 c0 01 83 c0 01 83 f8 00 74 f5}  //weight: 1, accuracy: High
        $x_1_5 = {9c 60 e8 00 00 00 00 5d 83 ed 07 8d 8d ?? ?? ff ff 80 39 01 0f 84 ?? ?? 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dogrobot_H_2147624449_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dogrobot.H"
        threat_id = "2147624449"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dogrobot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f5 61 81 7d e0 4b e1 22 00 0f 85}  //weight: 1, accuracy: High
        $x_1_2 = {39 41 08 77 09 c7 45 e4 0d 00 00 c0 eb}  //weight: 1, accuracy: High
        $x_1_3 = "\\??\\xzwinDOS" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dogrobot_L_2147629087_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dogrobot.gen!L"
        threat_id = "2147629087"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dogrobot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 43 01 89 45 e8 8b 45 e8 66 81 38 4d 5a 0f 85 ?? ?? ?? ?? 8b 45 e8 8b 70 3c 03 75 e8 8b 46 50 89 43 05 8b 45 e8 03 43 2f 8b 00 89 43 16 8b 45 e8 03 43 33 8b 00 89 43 1a 8b 45 e8 03 43 37 8b 00 89 43 1e 8d 43 26 50 ff 53 16}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 40 68 00 30 00 00 8b 43 0d 50 6a 00 ff 53 4f 89 45 cc 83 7d cc 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dogrobot_G_2147641800_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dogrobot.G!dll"
        threat_id = "2147641800"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dogrobot"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {3c e9 75 0b a1 01 ?? ?? ?? 8d ?? 05 ?? ?? ?? 8b 0f 33 c0 81 f9 ?? ?? ?? ?? 74}  //weight: 2, accuracy: Low
        $x_1_2 = {8b 44 24 1c 8b 0e 3b c8 75 10 8b 4c 24 20 55 51 56 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {6a 05 6a 18 8d 45 ?? 50 8d 4d ?? 51 8b 55 ?? 52 b8 ?? ?? ?? 86 ff d0}  //weight: 1, accuracy: Low
        $x_1_4 = "%c:\\Program files\\MSDN" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

