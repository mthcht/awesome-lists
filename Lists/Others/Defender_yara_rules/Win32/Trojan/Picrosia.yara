rule Trojan_Win32_Picrosia_A_2147726046_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Picrosia.A"
        threat_id = "2147726046"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Picrosia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 83 e8 20 0f b7 d7 8b ca 33 d2 f7 f1 66 f7 ef 66 05 ef 00 66 25 00 ff 66 83 c0 30 66 89 43 ea 83 c3 20 4e 0f 85 2d ff ff ff}  //weight: 1, accuracy: High
        $x_1_2 = "Shortcut.exe" wide //weight: 1
        $x_1_3 = "/a:c /t:\"" wide //weight: 1
        $x_1_4 = {6e 00 6f 00 2d 00 73 00 74 00 6f 00 72 00 65 00 [0-18] 4b 00 65 00 65 00 70 00 41 00 6c 00 69 00 76 00 65 00 [0-32] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_5 = {41 00 50 00 50 00 44 00 41 00 54 00 41 00 [0-16] 55 00 53 00 45 00 52 00 4e 00 41 00 4d 00 45 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Picrosia_B_2147726047_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Picrosia.B"
        threat_id = "2147726047"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Picrosia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c1 83 e8 20 0f b7 d7 8b ca 33 d2 f7 f1 66 f7 ef 66 05 ef 00 66 25 00 ff 66 83 c0 30 66 89 43 ea 83 c3 20 4e 0f 85 2d ff ff ff}  //weight: 1, accuracy: High
        $x_1_2 = "[ Tab ]" wide //weight: 1
        $x_1_3 = "[BACKSPACE]" wide //weight: 1
        $x_1_4 = "\\Recovery\\bin\\sys\\" wide //weight: 1
        $x_1_5 = "Exsist ::::" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Picrosia_C_2147726048_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Picrosia.C"
        threat_id = "2147726048"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Picrosia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c1 83 e8 20 0f b7 d7 8b ca 33 d2 f7 f1 66 f7 ef 66 05 ef 00 66 25 00 ff 66 83 c0 30 66 89 43 ea 83 c3 20 4e 0f 85 2d ff ff ff}  //weight: 1, accuracy: High
        $x_1_2 = "/win_downloader/windows/" wide //weight: 1
        $x_1_3 = "/C tasklist >" wide //weight: 1
        $x_1_4 = "kill_process" wide //weight: 1
        $x_1_5 = "run_patch" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Picrosia_D_2147726049_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Picrosia.D"
        threat_id = "2147726049"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Picrosia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 83 e8 20 0f b7 d7 8b ca 33 d2 f7 f1 66 f7 ef 66 05 ef 00 66 25 00 ff 66 83 c0 30 66 89 43 ea 83 c3 20 4e 0f 85 2d ff ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {55 00 53 00 45 00 52 00 4e 00 41 00 4d 00 45 00 [0-18] 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 58 00 50 00}  //weight: 1, accuracy: Low
        $x_1_3 = {69 00 74 00 6d 00 (31|32|33) 00 [0-6] 65 00 78 00 65}  //weight: 1, accuracy: Low
        $x_1_4 = {69 00 74 00 6d 00 (31|32|33) 00 [0-6] 6d 00 70 00 34}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Picrosia_E_2147726050_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Picrosia.E"
        threat_id = "2147726050"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Picrosia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 83 e8 20 0f b7 d7 8b ca 33 d2 f7 f1 66 f7 ef 66 05 ef 00 66 25 00 ff 66 83 c0 30 66 89 43 ea 83 c3 20 4e 0f 85 2d ff ff ff}  //weight: 1, accuracy: High
        $x_1_2 = "cmd.exe /C" wide //weight: 1
        $x_1_3 = "wmic DISKDRIVE get SerialNumber" wide //weight: 1
        $x_1_4 = "Win10Shell.exe" wide //weight: 1
        $x_1_5 = {6e 00 6f 00 2d 00 73 00 74 00 6f 00 72 00 65 00 [0-18] 4b 00 65 00 65 00 70 00 41 00 6c 00 69 00 76 00 65 00 [0-32] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

