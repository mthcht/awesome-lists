rule Backdoor_Win32_Jedobot_A_2147656371_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Jedobot.A"
        threat_id = "2147656371"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Jedobot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "%APPDATA%\\smss.exe" ascii //weight: 3
        $x_2_2 = "%SystemRoot%\\smss.exe" ascii //weight: 2
        $x_1_3 = "?p=BotRegister&" ascii //weight: 1
        $x_1_4 = "ddos.tcp" ascii //weight: 1
        $x_1_5 = "botmajor=" ascii //weight: 1
        $x_1_6 = "botcountry=" ascii //weight: 1
        $x_1_7 = "?p=BotPoke" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Jedobot_C_2147688689_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Jedobot.C"
        threat_id = "2147688689"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Jedobot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "115"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {00 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 00}  //weight: 100, accuracy: High
        $x_10_2 = "%APPDATA%\\smss.exe" wide //weight: 10
        $x_3_3 = {00 3f 70 3d 42 6f 74 50 6f 6b 65 00}  //weight: 3, accuracy: High
        $x_3_4 = {00 62 6f 74 6d 61 6a 6f 72 3d [0-2] 26 62 6f 74 6d 69 6e 6f 72 3d}  //weight: 3, accuracy: Low
        $x_1_5 = {00 64 64 6f 73 2e 74 63 70 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 64 64 6f 73 2e 75 64 70 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 64 64 6f 73 2e 68 74 74 70 00}  //weight: 1, accuracy: High
        $x_1_8 = "%SystemRoot%\\smss.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 2 of ($x_3_*))) or
            (all of ($x*))
        )
}

