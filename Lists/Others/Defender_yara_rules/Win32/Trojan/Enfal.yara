rule Trojan_Win32_Enfal_E_2147602710_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Enfal.E"
        threat_id = "2147602710"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Enfal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {55 6e 69 6e 73 74 61 6c 6c [0-4] 6f 6b [0-4] 66 61 69 6c [0-4] 75 70 6f 6b [0-4] 5c [0-4] 75 70 6c 6f 61 64 [0-4] 65 78 69 74 [0-4] 67 6f 6f 64 00}  //weight: 10, accuracy: Low
        $x_10_2 = "CreateToolhelp32Snapshot" ascii //weight: 10
        $x_5_3 = {8d 44 24 08 c7 44 24 08 28 01 00 00 50 56 e8 ?? ?? 00 00 85 c0 74 2d 8b 3d 0c 10 00 10 8d 4c 24 2c 51 68 ?? 20 00 10 ff d7 68 ?? ?? 00 10 68 ?? 20 00 10 ff d7 8d 54 24 08 52 56 e8 ?? ?? 00 00 85 c0 75 d9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Enfal_F_2147602711_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Enfal.F"
        threat_id = "2147602711"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Enfal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "windows\\currentversion\\explorer\\user shell folders" ascii //weight: 1
        $x_1_2 = {53 65 74 74 69 6e 67 73 5c 41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 5c 53 74 61 72 74 5c [0-10] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_3 = {2f 63 67 69 2d 62 69 6e 2f [0-6] 2e 63 67 69 00}  //weight: 1, accuracy: Low
        $x_1_4 = {56 8b 44 24 08 6a 0a 5e 03 c1 8a 96 ?? ?? ?? ?? 30 10 4e 79 ?? 41 3b 4c 24 0c 7c}  //weight: 1, accuracy: Low
        $x_1_5 = {8d 45 fc 50 68 3f 00 0f 00 8d 86 ?? ?? ?? ?? 53 50 68 01 00 00 80 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Enfal_F_2147602711_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Enfal.F"
        threat_id = "2147602711"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Enfal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "61"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "CreateRemoteThread" ascii //weight: 20
        $x_20_2 = "SeDebugPrivilege" ascii //weight: 20
        $x_10_3 = {8b 44 24 08 8b 4c 24 04 53 56 be 08 00 00 00 8a 11 8a 18 2a da 83 c1 04 88 18 8a 51 fd 8a 58 01 83 c0 02 2a da 4e 88 58 ff 75 e4 5e 5b c2 08 00}  //weight: 10, accuracy: High
        $x_10_4 = "/httpdocs/mm/" ascii //weight: 10
        $x_2_5 = "cgi-bin/Clnpp5.cgi" ascii //weight: 2
        $x_2_6 = "cgi-bin/Rwpq1.cgi" ascii //weight: 2
        $x_2_7 = "cgi-bin/Owpq4.cgi" ascii //weight: 2
        $x_2_8 = "cgi-bin/Dwpq3.cgi" ascii //weight: 2
        $x_2_9 = "cgi-bin/Crpq2.cgi" ascii //weight: 2
        $x_2_10 = "/Query.txt" ascii //weight: 2
        $x_2_11 = "/Ccmwhite" ascii //weight: 2
        $x_2_12 = "/Ufwhite" ascii //weight: 2
        $x_2_13 = "/Dfwhite" ascii //weight: 2
        $x_2_14 = "/Cmwhite" ascii //weight: 2
        $x_1_15 = "software\\microsoft\\windows nt\\currentversion\\winlogon" ascii //weight: 1
        $x_1_16 = "software\\microsoft\\windows\\currentversion\\run" ascii //weight: 1
        $x_1_17 = "exefile\\shell\\open\\command" ascii //weight: 1
        $x_1_18 = "txtfile\\shell\\open\\command" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 2 of ($x_10_*) and 9 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_20_*) and 2 of ($x_10_*) and 10 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_20_*) and 9 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_20_*) and 10 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_20_*) and 1 of ($x_10_*) and 4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_20_*) and 1 of ($x_10_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_20_*) and 1 of ($x_10_*) and 6 of ($x_2_*))) or
            ((2 of ($x_20_*) and 2 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_20_*) and 2 of ($x_10_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Enfal_H_2147654496_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Enfal.H"
        threat_id = "2147654496"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Enfal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 67 69 2d 62 69 6e 2f 63 6c 6e 70 70 35 2e 63 67 69 00}  //weight: 1, accuracy: High
        $x_1_2 = {63 67 69 2d 62 69 6e 2f ?? 77 70 71 ?? 2e 63 67 69}  //weight: 1, accuracy: Low
        $x_1_3 = {4e 46 61 6c 2e 65 78 65 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "software\\microsoft\\windows\\currentversion\\run" ascii //weight: 1
        $x_1_5 = {2f 43 6d 77 68 69 74 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

