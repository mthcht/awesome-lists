rule Backdoor_Win32_Morix_A_2147641104_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Morix.A"
        threat_id = "2147641104"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Morix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {81 78 04 02 01 00 00 0f 85 ?? 00 00 00 8b 4d ?? 83 79 08 7f 77 ?? 8b 55 ?? 83 7a 08 14}  //weight: 2, accuracy: Low
        $x_3_2 = {8b 55 08 03 55 ?? 0f be 02 83 f0 62 8b 4d ?? 03 4d ?? 88 01 eb}  //weight: 3, accuracy: Low
        $x_1_3 = "\\startup\\360tray.exe" ascii //weight: 1
        $x_1_4 = "_kaspersky" ascii //weight: 1
        $x_1_5 = {00 5c 6b 65 79 6c 6f 67 2e 64 61 74 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 45 6e 61 62 6c 65 41 64 6d 69 6e 54 53 52 65 6d 6f 74 65 00}  //weight: 1, accuracy: High
        $x_1_7 = "CurrentControlSet\\Control\\Terminal Server\\RDPTcp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Morix_I_2147652724_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Morix.I"
        threat_id = "2147652724"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Morix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "mozheUpdate" ascii //weight: 1
        $x_1_2 = {f3 ab 6a 00 c6 45 f4 51 c6 45 f5 33 c6 45 f6 36 c6 45 f7 30 c6 45 f8 53 c6 45 f9 44 c6 45 fa 43 c6 45 fb 6c c6 45 fc 61 c6 45 fd 73 c6 45 fe 73 66 ab ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 50 ff d6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Morix_J_2147657040_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Morix.J"
        threat_id = "2147657040"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Morix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\secivreS\\teSlortnoCtnerruC\\METSYS" ascii //weight: 1
        $x_1_2 = "system\\cURRENTcONTROLSET\\sERVICES\\tERMSERVICE" ascii //weight: 1
        $x_1_3 = "CMD.EXE /C NET USER GUEST /ACTIVE:YES && NET USER GUEST" ascii //weight: 1
        $x_1_4 = "0NOGOLNIw\\NOISREvTNERRUc\\tn SWODNIw\\TFOSORCIm\\erawtfos" ascii //weight: 1
        $x_5_5 = {c6 85 58 5e ff ff 4e c6 85 59 5e ff ff 57 c6 85 5a 5e ff ff 41 c6 85 5b 5e ff ff 41 c6 85 5c 5e ff ff 41 c6 85 5d 5e ff ff 41 c6 85 5e 5e ff ff 5c c6 85 5f 5e ff ff 42 c6 85 60 5e ff ff 4c c6 85 61 5e ff ff 41 c6 85 62 5e ff ff 43 c6 85 63 5e ff ff 4b}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

