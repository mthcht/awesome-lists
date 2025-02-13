rule Worm_Win32_Xtrat_B_2147694636_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Xtrat.B"
        threat_id = "2147694636"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Xtrat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {75 00 70 00 64 00 61 00 74 00 65 00 73 00 65 00 72 00 76 00 65 00 72 00 6c 00 6f 00 63 00 61 00 6c 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "downexec" wide //weight: 1
        $x_1_3 = "Xtreme RAT" wide //weight: 1
        $x_1_4 = "UnitFuncoesDiversas" ascii //weight: 1
        $x_1_5 = "UnitKeylogger" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Xtrat_B_2147694637_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Xtrat.B!A"
        threat_id = "2147694637"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Xtrat"
        severity = "Critical"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "XTREME" wide //weight: 1
        $x_1_2 = "Xtreme RAT" ascii //weight: 1
        $x_1_3 = {55 6e 69 74 43 6f 6e 66 69 67 73 00}  //weight: 1, accuracy: High
        $x_1_4 = {55 6e 69 74 43 72 79 70 74 53 74 72 69 6e 67 00}  //weight: 1, accuracy: High
        $x_1_5 = "UnitKeylogger" ascii //weight: 1
        $x_1_6 = {45 64 69 74 53 76 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Worm_Win32_Xtrat_B_2147694640_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Xtrat.B!B"
        threat_id = "2147694640"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Xtrat"
        severity = "Critical"
        info = "B: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {58 00 54 00 52 00 45 00 4d 00 45 00 00 00}  //weight: 5, accuracy: High
        $x_1_2 = {55 6e 69 74 53 65 72 76 65 72 43 6f 6e 66 69 67 73 00}  //weight: 1, accuracy: High
        $x_1_3 = {45 64 69 74 53 76 72 00}  //weight: 1, accuracy: High
        $x_1_4 = {55 6e 69 74 43 6f 6e 73 74 61 6e 74 65 73 00}  //weight: 1, accuracy: High
        $x_1_5 = {55 6e 69 74 43 72 79 70 74 53 74 72 69 6e 67 00}  //weight: 1, accuracy: High
        $x_1_6 = {55 6e 69 74 49 6e 6a 65 63 74 53 65 72 76 65 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Xtrat_B_2147696723_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Xtrat.B!C"
        threat_id = "2147696723"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Xtrat"
        severity = "Critical"
        info = "C: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {58 00 74 00 72 00 65 00 6d 00 65 00 20 00 52 00 41 00 54 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {50 00 45 00 52 00 53 00 49 00 53 00 54 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "Xtreme RAT Unicode\\Servidor\\" ascii //weight: 1
        $x_1_4 = {55 6e 69 74 43 6f 6e 65 78 61 6f 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Xtrat_D_2147696945_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Xtrat.D"
        threat_id = "2147696945"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Xtrat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "*\\AC:\\Users\\Roda\\Desktop\\under\\Under0deando.vbp" wide //weight: 10
        $x_1_2 = "reg add hkcu\\software\\microsoft\\windows\\currentversion\\policies\\system /v disableregistrytools /t reg_dword /d" wide //weight: 1
        $x_1_3 = "reg add hkcu\\software\\microsoft\\windows\\currentversion\\policies\\system /v DisableTaskMgr /t reg_dword /d" wide //weight: 1
        $x_1_4 = "avgtray.exe" wide //weight: 1
        $x_1_5 = "avgwdsvc.exe" wide //weight: 1
        $x_1_6 = "EGUI.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Xtrat_E_2147697739_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Xtrat.E"
        threat_id = "2147697739"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Xtrat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ImSecureRAT" wide //weight: 1
        $x_1_2 = {50 00 45 00 52 00 53 00 49 00 53 00 54 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "downexec" wide //weight: 1
        $x_1_4 = {55 6e 69 74 43 6f 6e 65 78 61 6f 00}  //weight: 1, accuracy: High
        $x_1_5 = "UnitFuncoesDiversas" ascii //weight: 1
        $x_1_6 = "UnitKeylogger" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Xtrat_F_2147706282_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Xtrat.F"
        threat_id = "2147706282"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Xtrat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {25 55 73 65 72 43 6f 6e 6e 65 63 74 69 6f 6e 00}  //weight: 1, accuracy: High
        $x_1_2 = {72 00 65 00 67 00 20 00 61 00 64 00 64 00 20 00 22 00 48 00 4b 00 45 00 59 00 5f 00 43 00 55 00 52 00 52 00 45 00 4e 00 54 00 5f 00 55 00 53 00 45 00 52 00 5c 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 45 00 72 00 72 00 6f 00 72 00 20 00 52 00 65 00 70 00 6f 00 72 00 74 00 69 00 6e 00 67 00 22 00 20 00 2f 00 76 00 20 00 44 00 6f 00 6e 00 74 00 53 00 68 00 6f 00 77 00 55 00 49 00 20 00 2f 00 74 00 20 00 52 00 45 00 47 00 5f 00 44 00 57 00 4f 00 52 00 44 00 20 00 2f 00 64 00 20 00 31 00 20 00 2f 00 66 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {53 00 70 00 65 00 63 00 69 00 61 00 6c 00 46 00 6f 00 6c 00 64 00 65 00 72 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {43 00 72 00 65 00 61 00 74 00 65 00 53 00 68 00 6f 00 72 00 74 00 63 00 75 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {54 00 6d 00 70 00 53 00 6f 00 6c 00 75 00 74 00 69 00 6f 00 6e 00 32 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {5c 00 54 00 6d 00 70 00 53 00 6f 00 6c 00 75 00 74 00 69 00 6f 00 6e 00 32 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Xtrat_G_2147715811_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Xtrat.G"
        threat_id = "2147715811"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Xtrat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 6e 69 74 43 72 79 70 74 53 74 72 69 6e 67 00}  //weight: 1, accuracy: High
        $x_1_2 = {54 53 65 72 76 65 72 4b 65 79 6c 6f 67 67 65 72 00}  //weight: 1, accuracy: High
        $x_1_3 = {32 46 75 6e 63 74 69 6f 6e 73 00}  //weight: 1, accuracy: High
        $x_1_4 = {55 6e 69 74 43 6f 6e 66 69 67 73 00}  //weight: 1, accuracy: High
        $x_1_5 = "XTREME" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

