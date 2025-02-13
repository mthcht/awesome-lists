rule Ransom_Win32_Somhoveran_A_2147678661_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Somhoveran.A"
        threat_id = "2147678661"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Somhoveran"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "220"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {be 3c 00 00 00 99 f7 fe 89 55 fc 8b c1 b9 10 0e 00 00 99 f7 f9 8b f0 8d 45 f4 50 89 75 dc c6 45 e0 00 8b 45 fc}  //weight: 100, accuracy: High
        $x_50_2 = {cd e5 e2 e5 f0 ed fb e9 20 ea ee e4 21 00}  //weight: 50, accuracy: High
        $x_50_3 = {cf f0 e5 e2 fb f8 e5 ed 20 eb e8 ec e8 f2 20 ef ee ef fb f2 ee ea 21}  //weight: 50, accuracy: High
        $x_30_4 = {32 33 3a 33 30 3a 30 30 00}  //weight: 30, accuracy: High
        $x_30_5 = "93872354601187439" ascii //weight: 30
        $x_20_6 = "ServiceAntiWinLocker.exe" ascii //weight: 20
        $x_20_7 = "AntiWinLockerTray.exe" ascii //weight: 20
        $x_20_8 = "NoManageMyComputerVerb" ascii //weight: 20
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_50_*) and 2 of ($x_30_*) and 3 of ($x_20_*))) or
            ((1 of ($x_100_*) and 2 of ($x_30_*) and 3 of ($x_20_*))) or
            ((1 of ($x_100_*) and 1 of ($x_50_*) and 1 of ($x_30_*) and 2 of ($x_20_*))) or
            ((1 of ($x_100_*) and 1 of ($x_50_*) and 2 of ($x_30_*) and 1 of ($x_20_*))) or
            ((1 of ($x_100_*) and 2 of ($x_50_*) and 1 of ($x_20_*))) or
            ((1 of ($x_100_*) and 2 of ($x_50_*) and 1 of ($x_30_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Somhoveran_B_2147695432_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Somhoveran.B"
        threat_id = "2147695432"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Somhoveran"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {be 3c 00 00 00 99 f7 fe 89 55 fc 8b c1 b9 10 0e 00 00 99 f7 f9 8b f0 8d 45 f4 50 89 75 dc c6 45 e0 00 8b 45 fc}  //weight: 1, accuracy: High
        $x_1_2 = {cd e5 e2 e5 f0 ed fb e9 20 ea ee e4 21 00}  //weight: 1, accuracy: High
        $x_1_3 = "ServiceAntiWinLocker.exe" ascii //weight: 1
        $x_1_4 = "AntiWinLockerTray.exe" ascii //weight: 1
        $x_1_5 = "Warning! Windows Blocked!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Somhoveran_C_2147697335_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Somhoveran.C"
        threat_id = "2147697335"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Somhoveran"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ef e5 f0 e5 e7 e0 e3 f0 f3 e7 e8 f8 fc 20 e2 e8 ed e4 e0 20 e4 e0 eb e8 f2 f1 ff 00}  //weight: 1, accuracy: High
        $x_1_2 = {57 69 6e 64 6f 77 73 20 e7 e0 e1 eb ee ea e8 f0 ee e2 e0 ed 21 00}  //weight: 1, accuracy: High
        $x_1_3 = {41 6e 74 69 57 69 6e 4c 6f 63 6b 65 72 54 72 61 79 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_4 = "Information about blocking" ascii //weight: 1
        $x_1_5 = "To removing the system:" ascii //weight: 1
        $x_1_6 = {be 3c 00 00 00 99 f7 fe 89 55 f8 8b c1 be 3c 00 00 00 99 f7 fe be 3c 00 00 00 99 f7 fe 89 55 fc 8b c1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Ransom_Win32_Somhoveran_D_2147733494_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Somhoveran.D!bit"
        threat_id = "2147733494"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Somhoveran"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {be 3c 00 00 00 99 f7 fe 89 55 fc 8b c1 b9 10 0e 00 00 99 f7 f9 8b f0 8d 45 f4 50 89 75 dc c6 45 e0 00 8b 45 fc}  //weight: 1, accuracy: High
        $x_1_2 = {cd e5 e2 e5 f0 ed fb e9 20 ea ee e4 21 00}  //weight: 1, accuracy: High
        $x_1_3 = "ServiceAntiWinLocker.exe" ascii //weight: 1
        $x_1_4 = "AntiWinLockerTray.exe" ascii //weight: 1
        $x_1_5 = "You are locked by" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

