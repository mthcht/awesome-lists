rule TrojanSpy_Win32_Bholog_B_2147696324_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Bholog.B"
        threat_id = "2147696324"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bholog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6f 73 73 6b [0-12] 66 72 6d 4c 6f 67 69 6e}  //weight: 2, accuracy: Low
        $x_2_2 = "[ALTUP]" wide //weight: 2
        $x_2_3 = "[PASTE]" wide //weight: 2
        $x_1_4 = {72 65 61 64 69 6e 67 00 72 65 70 62 68 61 69}  //weight: 1, accuracy: High
        $x_1_5 = {69 6b 6b 00 72 61 73 74 61 62 72 6f 00}  //weight: 1, accuracy: High
        $x_1_6 = {53 00 65 00 6c 00 65 00 63 00 74 00 20 00 2a 00 20 00 66 00 72 00 6f 00 6d 00 20 00 44 00 61 00 74 00 41 00 63 00 63 00 6f 00 75 00 6e 00 74 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {64 69 6b 68 61 78 00 00 44 61 74 41 63 63 65 73 73 00}  //weight: 1, accuracy: High
        $x_1_8 = {3a 00 5c 00 64 00 65 00 6b 00 68 00 74 00 65 00 5f 00 68 00 65 00 69 00 6e 00 5c 00 64 00 65 00 65 00 2e 00 76 00 62 00 70 00 00 00}  //weight: 1, accuracy: High
        $x_1_9 = {61 6c 74 61 66 5f 62 68 61 69 00}  //weight: 1, accuracy: High
        $x_1_10 = {4c 6f 67 69 6e 53 75 63 63 65 65 64 65 64 00}  //weight: 1, accuracy: High
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

rule TrojanSpy_Win32_Bholog_B_2147696324_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Bholog.B"
        threat_id = "2147696324"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bholog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Monitors and records Internet connection." wide //weight: 1
        $x_1_2 = "http://www.thongkorn.com/MyIP.php" wide //weight: 1
        $x_1_3 = {00 00 5c 00 4c 00 6f 00 67 00 67 00 69 00 6e 00 67 00 2e 00 74 00 78 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "Select * from DatAccounts" wide //weight: 1
        $x_1_5 = "frmMonitorInternet" ascii //weight: 1
        $x_2_6 = "\\dekhtesd_heinsd\\fdfdf.vbp" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Bholog_B_2147710063_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Bholog.B!gen"
        threat_id = "2147710063"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bholog"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".jpg" ascii //weight: 1
        $x_1_2 = ".mdb" wide //weight: 1
        $x_1_3 = "sendmeyar" ascii //weight: 1
        $x_1_4 = "dikhao" ascii //weight: 1
        $x_1_5 = "broda" ascii //weight: 1
        $x_1_6 = "Module1j" ascii //weight: 1
        $x_1_7 = "txtpassword" ascii //weight: 1
        $x_1_8 = "LoginSucceeded" ascii //weight: 1
        $x_1_9 = "PC:&nbsp;&nbsp;&nbsp;" ascii //weight: 1
        $x_1_10 = "type=\"submit\" value=\"hsd\"" ascii //weight: 1
        $x_1_11 = {53 00 65 00 6c 00 65 00 63 00 74 00 [0-32] 2e 00 2a 00 [0-16] 46 00 72 00 6f 00 6d 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

rule TrojanSpy_Win32_Bholog_C_2147716927_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Bholog.C!bit"
        threat_id = "2147716927"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bholog"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6f 73 73 6b [0-12] 66 72 6d 4c 6f 67 69 6e}  //weight: 1, accuracy: Low
        $x_1_2 = "[ALTUP]" wide //weight: 1
        $x_1_3 = {61 6c 74 61 66 5f 62 68 61 69 00}  //weight: 1, accuracy: High
        $x_1_4 = {4c 6f 67 69 6e 53 75 63 63 65 65 64 65 64 00}  //weight: 1, accuracy: High
        $x_1_5 = "PC:&nbsp;&nbsp;&nbsp;" ascii //weight: 1
        $x_1_6 = "mere ko dikhao" ascii //weight: 1
        $x_1_7 = {73 65 6e 64 6d 65 79 61 72 00}  //weight: 1, accuracy: High
        $x_1_8 = {4d 6f 64 75 6c 65 31 6a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Bholog_D_2147728055_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Bholog.D!bit"
        threat_id = "2147728055"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bholog"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {00 00 77 00 6f 00 72 00 6b 00 67 00 72 00 61 00 63 00 65 00 00 00}  //weight: 5, accuracy: High
        $x_1_2 = "[PASTE]" wide //weight: 1
        $x_1_3 = "[++++]" wide //weight: 1
        $x_1_4 = "[Passwords]" wide //weight: 1
        $x_1_5 = "[SSSSS]" wide //weight: 1
        $x_1_6 = "cmd.exe /c" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

