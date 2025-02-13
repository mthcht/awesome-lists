rule TrojanSpy_Win32_Usteal_B_2147646434_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Usteal.B"
        threat_id = "2147646434"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Usteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 46 52 5f 53 74 65 61 6c 65 72 5f 32 33 31 30 00}  //weight: 1, accuracy: High
        $x_1_2 = {52 65 67 69 73 74 72 79 2d 47 72 61 62 62 69 6e 67 2e 72 65 67 00}  //weight: 1, accuracy: High
        $x_1_3 = {25 30 32 68 75 2d 25 30 32 68 75 2d 25 68 75 5f 25 30 32 68 75 2d 25 30 32 68 75 2d 25 30 32 68 75 00}  //weight: 1, accuracy: High
        $x_1_4 = {44 69 73 70 6c 61 79 4e 61 6d 65 00 54 72 6f 6c 6f 6c 6f 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Usteal_C_2147653615_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Usteal.C"
        threat_id = "2147653615"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Usteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "UFR_Stealer_" ascii //weight: 10
        $x_1_2 = "encryptedUsername, encryptedPassword FROM moz_logins" ascii //weight: 1
        $x_1_3 = "Opera\\wand.dat" ascii //weight: 1
        $x_1_4 = "Ghisler\\Total Commander" ascii //weight: 1
        $x_1_5 = ".purple\\accounts.xml" ascii //weight: 1
        $x_1_6 = "Google Talk\\Accounts" ascii //weight: 1
        $x_1_7 = "%02hu-%02hu-%hu_%02hu-%02hu-%02hu_%s" ascii //weight: 1
        $x_1_8 = "Registry-Grabbing.reg" ascii //weight: 1
        $x_1_9 = "dokotaaaa.hop.ru" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Usteal_D_2147655153_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Usteal.D"
        threat_id = "2147655153"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Usteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "UFR Stealer Report [ %s ]" ascii //weight: 1
        $x_1_2 = {72 65 70 6f 72 74 5f 00 2e 62 69 6e 00 4e 4f 5f 50 57 44 53 5f}  //weight: 1, accuracy: High
        $x_1_3 = {46 54 50 00 2a 00 46 69 6c 65 2d 50 61 74 68 73 2e 74 78 74 00 46 69 6c 65 73 2d 41 72 65 2d 43 6f 70 69 65 64 2e 74 78 74 00 41 50 50 44 41 54 41 00 55 46 52}  //weight: 1, accuracy: High
        $x_1_4 = {66 74 70 2e 66 72 6f 6e 74 2e 72 75 [0-16] 6d 61 6a 65 73 74 69 63 6b 31 32 [0-16] 6d 6a 31 32 67 70 33 32 30}  //weight: 1, accuracy: Low
        $x_1_5 = {68 ff 00 00 00 ff 75 fc 6a 01 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 15 68 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? a3 ?? ?? ?? ?? 0b c0 75 11 ff 35 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? e9 b2 ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanSpy_Win32_Usteal_A_2147655156_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Usteal.gen!A"
        threat_id = "2147655156"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Usteal"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "UFR Stealer Report" ascii //weight: 1
        $x_1_2 = "%02hu-%02hu-%hu_%02hu-%02hu-%02hu" ascii //weight: 1
        $x_2_3 = {8d 74 13 0d 0f bf 3e 83 c6 02 60 57 56 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 61 0f bf 05 ?? ?? ?? ?? 66 3d 49 43 0f 85 ?? ?? 00 00 03 f7 0f be 06 8d 74 30 01 0f be 3e}  //weight: 2, accuracy: Low
        $x_2_4 = {80 04 08 fb 40 3b c7 72 ?? 60 ff 75 e4 6a 00 ff 35 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 61 e9 ?? ?? 00 00 66 3d 4a 41 0f 85}  //weight: 2, accuracy: Low
        $x_2_5 = {81 fb a7 81 00 00 74 18 81 fb a6 81 00 00 74 10 81 fb 79 81 00 00 74 08 81 fb 59 81 00 00 75 0c 60 e8 ?? ?? ?? ?? 61 eb 03 83 c6 0c 49 75}  //weight: 2, accuracy: Low
        $x_2_6 = {74 15 8b c8 33 d2 8b 75 08 8b fe ac 02 c2 f6 d0 fe c8 aa 42 49 75 f4}  //weight: 2, accuracy: High
        $x_2_7 = {ac 84 c0 74 05 41 3b cb 75 f6 83 e9 02 8d 35 ?? ?? ?? ?? 8d 3d ?? ?? ?? ?? 8a 15 ?? ?? ?? ?? 32 15 ?? ?? ?? ?? 80 ca ?? ac 32 c2 aa 49 75 f9}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Usteal_F_2147670568_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Usteal.F"
        threat_id = "2147670568"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Usteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "winpckg.exe" ascii //weight: 1
        $x_1_2 = "rainy_day_today" ascii //weight: 1
        $x_1_3 = "install.pck" ascii //weight: 1
        $x_1_4 = "Rainy Keylogger Logs [ %s ]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

