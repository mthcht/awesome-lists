rule Virus_Win32_Xpaj_A_2147611506_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Xpaj.gen!A"
        threat_id = "2147611506"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Xpaj"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 52 65 63 79 c7 ?? 06 63 6c 65 64 c7 ?? 0a 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {61 75 74 6f c7 ?? ?? 04 72 75 6e 2e c7 ?? ?? 08 69 6e 66 00}  //weight: 1, accuracy: Low
        $x_1_3 = {61 75 74 6f c7 ?? ?? 04 72 75 6e 2e c7 ?? ?? 08 65 78 65 00}  //weight: 1, accuracy: Low
        $x_2_4 = {2a 2e 2a 00 8d ?? ec c7 ?? 2e 65 78 65 c7 ?? 04 2e 64 6c 6c c7 ?? 08 2e 73 63 72 c7 ?? 0c 2e 73 79 73}  //weight: 2, accuracy: Low
        $x_1_5 = {2e 63 6f 6d 0f 84 ?? ?? 00 00 81 ?? 2e 69 6e 66 0f 84 ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_6 = {0d 20 20 20 20 3d 68 74 74 70 0f 84}  //weight: 1, accuracy: High
        $x_1_7 = {c7 44 24 5e 2e 6f 72 67}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Virus_Win32_Xpaj_B_2147642353_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Xpaj.gen!B"
        threat_id = "2147642353"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Xpaj"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {61 75 74 6f c7 ?? ?? 04 72 75 6e 2e c7 ?? ?? (08 69|08 65) 00}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 65 78 65 c7 ?? 04 2e 64 6c 6c c7 ?? 08 2e 73 63 72 c7 ?? 0c 2e 73 79 73}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 63 6f 6d 0f 84 ?? ?? 00 00 81 ?? 2e 69 6e 66 0f 84 ?? ?? 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Virus_Win32_Xpaj_C_2147649568_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Xpaj.gen!C"
        threat_id = "2147649568"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Xpaj"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 41 04 2e 64 6c 6c c7 41 08 2e 73 63 72}  //weight: 1, accuracy: High
        $x_1_2 = {61 75 74 6f c7 44 ?? 04 72 75 6e 2e c7 44 00 08 (65|69) 00 13 00 c7 04 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Xpaj_D_2147651292_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Xpaj.gen!D"
        threat_id = "2147651292"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Xpaj"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = "hAVERhFUCK" ascii //weight: 4
        $x_4_2 = {81 7e 03 70 3a 2f 2f 0f 84 0d 00 00 00 81 7e 03 50 3a 2f 2f 0f 85 ?? ?? 00 00}  //weight: 4, accuracy: Low
        $x_4_3 = {c7 47 04 69 63 65 5c}  //weight: 4, accuracy: High
        $x_4_4 = {c7 07 63 3a 5c 00 6a 00 6a 00 6a 00 6a 00}  //weight: 4, accuracy: High
        $x_1_5 = "://opendashell.com" ascii //weight: 1
        $x_1_6 = "://chopchopchup.com" ascii //weight: 1
        $x_1_7 = "://gustobla.com" ascii //weight: 1
        $x_1_8 = "://saltodemortallex.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 4 of ($x_1_*))) or
            ((3 of ($x_4_*))) or
            (all of ($x*))
        )
}

