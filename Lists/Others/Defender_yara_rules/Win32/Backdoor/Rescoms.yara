rule Backdoor_Win32_Rescoms_A_2147716902_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Rescoms.A!bit"
        threat_id = "2147716902"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Rescoms"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Remcos_Mutex_Inj" ascii //weight: 1
        $x_1_2 = "EnableLUA /t REG_DWORD /d 0" ascii //weight: 1
        $x_1_3 = "BreakingSecurity RAT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Rescoms_B_2147719326_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Rescoms.B"
        threat_id = "2147719326"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Rescoms"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "startcamcap" ascii //weight: 1
        $x_1_2 = "autofflinelogs" ascii //weight: 1
        $x_1_3 = "autopswdata" ascii //weight: 1
        $x_1_4 = "downloadfromurltofile" ascii //weight: 1
        $x_1_5 = "startonlinekl" ascii //weight: 1
        $x_1_6 = "getscrslist" ascii //weight: 1
        $x_1_7 = "screenshotdata" ascii //weight: 1
        $x_5_8 = "Connected to C&C!" ascii //weight: 5
        $x_5_9 = "Remcos_Mutex_Inj" ascii //weight: 5
        $x_5_10 = "Breaking-Security.Net" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 6 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            ((3 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Rescoms_C_2147728905_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Rescoms.C!bit"
        threat_id = "2147728905"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Rescoms"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Remcos_Mutex_Inj" ascii //weight: 1
        $x_1_2 = "Keylogger Started" ascii //weight: 1
        $x_1_3 = "Uploading file to C&C" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Rescoms_D_2147730434_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Rescoms.D!bit"
        threat_id = "2147730434"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Rescoms"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 fc 8a 54 1a ff 8b 4d f8 8a 4c 19 ff 32 d1 88 54 18 ff 43 4e 75 e1}  //weight: 1, accuracy: High
        $x_1_2 = {8b 55 fc 8a 1a 8b d3 c1 e2 04 33 c9 8a cb c1 e9 04 0a d1 88 10}  //weight: 1, accuracy: High
        $x_1_3 = {73 76 63 68 6f 73 74 2e 65 78 65 [0-16] 53 74 69 6b 79 4e 6f 74 2e 65 78 65 [0-16] 53 79 6e 63 48 6f 73 74 2e 65 78 65 [0-16] 73 79 73 74 72 61 79 2e 65 78 65 [0-16] 74 61 73 6b 65 6e 67 2e 65 78 65 [0-16] 74 61 73 6b 6c 69 73 74 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win32_Rescoms_KD_2147760038_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Rescoms.KD"
        threat_id = "2147760038"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Rescoms"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 00 03 c6 0f b7 0b 66 81 e1 ff 0f 0f b7 c9 03 c1 01 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

