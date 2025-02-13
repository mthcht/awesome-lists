rule Worm_Win32_Kelvir_B_2147602735_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Kelvir.gen!B"
        threat_id = "2147602735"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Kelvir"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "42"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "KelVir" ascii //weight: 10
        $x_10_2 = "The RPMiSO Group" wide //weight: 10
        $x_10_3 = "objmessenger" ascii //weight: 10
        $x_10_4 = "MessengerAPI" ascii //weight: 10
        $x_1_5 = "{ENTER}" wide //weight: 1
        $x_1_6 = "~C:\\Program Files\\Messenger\\msmsgs.exe\\3" ascii //weight: 1
        $x_1_7 = "~C:\\Program Files\\MSN Messenger\\msnmsgr.exe\\2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Kelvir_C_2147621248_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Kelvir.gen!C"
        threat_id = "2147621248"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Kelvir"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "203"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {5c 4d 65 73 73 65 6e 67 65 72 5c 6d 73 6d 73 67 73 2e 65 78 65 5c 33 [0-6] 4d 65 73 73 65 6e 67 65 72 41 50 49}  //weight: 100, accuracy: Low
        $x_100_2 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c 00}  //weight: 100, accuracy: High
        $x_3_3 = "CALL IT MSN.RWNT K THX" wide //weight: 3
        $x_3_4 = {70 00 69 00 63 00 74 00 75 00 72 00 65 00 73 00 2e 00 70 00 68 00 70 00 3f 00 65 00 6d 00 61 00 69 00 6c 00 3d 00 00 00}  //weight: 3, accuracy: High
        $x_3_5 = {43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 00 00 00 00 00 54 00 68 00 65 00 20 00 52 00 50 00 4d 00 69 00 53 00 4f 00 20 00 47 00 72 00 6f 00 75 00 70 00}  //weight: 3, accuracy: High
        $x_1_6 = "Get contact list and sort" ascii //weight: 1
        $x_1_7 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_8 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 41 6e 64 52 75 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 3 of ($x_1_*))) or
            ((2 of ($x_100_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Kelvir_D_2147647323_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Kelvir.gen!D"
        threat_id = "2147647323"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Kelvir"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "{ENTER}" wide //weight: 1
        $x_2_2 = "C:\\Program Files\\Messenger\\msmsgs.exe\\3" ascii //weight: 2
        $x_3_3 = "SaveAppToWin_ini" ascii //weight: 3
        $x_1_4 = "MessengerAPI" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

