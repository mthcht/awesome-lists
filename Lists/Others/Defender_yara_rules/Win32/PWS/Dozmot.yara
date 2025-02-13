rule PWS_Win32_Dozmot_A_2147621256_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Dozmot.A"
        threat_id = "2147621256"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Dozmot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {44 44 44 2e 64 6c 6c 00 4c 70 6b 44 6c 6c 49 6e}  //weight: 6, accuracy: High
        $x_1_2 = {67 61 6d 65 73 65 74 2e 64 61 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {67 61 6d 65 66 6f 6e 74 2e 64 61 74 00}  //weight: 1, accuracy: High
        $x_1_4 = {57 6f 77 49 6e 69 74 63 6f 64 65 2e 64 61 74 00}  //weight: 1, accuracy: High
        $x_1_5 = {74 65 78 74 66 6f 6e 74 2e 64 61 74 00}  //weight: 1, accuracy: High
        $x_1_6 = {44 4e 46 63 68 69 6e 61 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_7 = {63 61 62 61 6c 66 6f 6e 74 2e 64 61 74 00}  //weight: 1, accuracy: High
        $x_6_8 = {74 7c 53 8b 1d ?? ?? ?? ?? 56 6a 02 57 68 ec fe ff ff 50 ff d3}  //weight: 6, accuracy: Low
        $x_1_9 = {68 04 c0 00 08 50 89 75 f8 ff 15}  //weight: 1, accuracy: High
        $x_6_10 = {7e 24 53 56 8b 74 24 18 8b dd 2b de 8a 04 33 55 04 ?? 34 ?? 2c}  //weight: 6, accuracy: Low
        $x_1_11 = {c3 2b de c6 06 e9 8d 83 ?? ?? ?? ?? 8b c8 8b d0 c1 e9 08}  //weight: 1, accuracy: Low
        $x_7_12 = {eb 23 e8 8e fe ff ff eb 18 8b 46 0c 85 c0 75 07 b8 01 00 00 c0 eb 23 ff 70 04 ff 30 e8 d4 fb ff ff}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_1_*))) or
            ((2 of ($x_6_*))) or
            ((1 of ($x_7_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Dozmot_B_2147621659_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Dozmot.B"
        threat_id = "2147621659"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Dozmot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {2b de 8a 04 33 55 04 ?? 34 ?? 2c ?? 47 88 06 46 ff 15 28 60 00 10 3b f8 7c e8}  //weight: 4, accuracy: Low
        $x_1_2 = {2f 31 47 65 74 4d 62 2e 61 73 70 00}  //weight: 1, accuracy: High
        $x_1_3 = {26 6d 62 68 3d 00}  //weight: 1, accuracy: High
        $x_1_4 = "action=domod&" ascii //weight: 1
        $x_1_5 = "=showmbm&" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Dozmot_C_2147626006_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Dozmot.C"
        threat_id = "2147626006"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Dozmot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {ff d3 3d e5 03 00 00 74 0b 3d 31 04 00 00 74 04 33 db}  //weight: 2, accuracy: High
        $x_2_2 = {80 f9 41 7c 0d 80 f9 4d 7f 08 0f be c9 83 c1 ?? eb 1f}  //weight: 2, accuracy: Low
        $x_2_3 = {c1 e6 19 c1 e8 07 0b f0 0f be c1 8a 4a 01 03 c6 42 84 c9 75 e9}  //weight: 2, accuracy: High
        $x_1_4 = "%s?u=%s&sha=%s&p=%s" ascii //weight: 1
        $x_1_5 = "%s/lin.php?m=%s&g=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Dozmot_D_2147633342_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Dozmot.D"
        threat_id = "2147633342"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Dozmot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "name=\"trackdata\";" ascii //weight: 2
        $x_2_2 = "name=\"submitted\"" ascii //weight: 2
        $x_1_3 = {00 69 73 6f 6e 6c 69 6e 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 2f 66 6c 61 73 68 2e 61 73 70}  //weight: 1, accuracy: High
        $x_2_5 = {00 33 36 30 53 45 2e 65 78 65 00}  //weight: 2, accuracy: High
        $x_2_6 = {00 26 7a 74 3d 73 75 63 63 6d 62 68 00}  //weight: 2, accuracy: High
        $x_2_7 = "---------7b4a6d158c9" ascii //weight: 2
        $x_1_8 = {00 61 63 74 69 6f 6e 3d 75 70 26}  //weight: 1, accuracy: High
        $x_2_9 = {42 4d 89 5c 24 [0-11] c7 44 24 ?? 36 00 00 00 ff}  //weight: 2, accuracy: Low
        $x_2_10 = {f7 ff ff 5c c6 85 ?? f7 ff ff 63 c6 85 ?? f7 ff ff 75 c6 85 ?? f7 ff ff 72 c6 85 ?? f7 ff ff 72 c6 85 ?? f7 ff ff 65 c6 85 ?? f7 ff ff 6e c6 85 ?? f7 ff ff 74 c6 85 ?? f7 ff ff 73 c6 85 ?? f7 ff ff 65 c6 85 ?? f7 ff ff 72 c6 85 ?? f7 ff ff 76 c6 85 ?? f7 ff ff 65 c6 85 ?? f7 ff ff 72 c6 85 ?? f7 ff ff 2e c6 85 ?? f7 ff ff 69 c6 85 ?? f7 ff ff 6e c6 85 ?? f7 ff ff 69}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((5 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Dozmot_E_2147638410_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Dozmot.E"
        threat_id = "2147638410"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Dozmot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 06 8a 0f 32 d1 02 d1 32 c2 d2 c8 88 06}  //weight: 1, accuracy: High
        $x_1_2 = {c6 04 02 e9 8b cb 2b ca 83 e9 05}  //weight: 1, accuracy: High
        $x_1_3 = "%s?action=postmb&u=%s&mb=%s" ascii //weight: 1
        $x_1_4 = "&fid=%s&lev=%d&jb=%d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule PWS_Win32_Dozmot_F_2147638491_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Dozmot.F"
        threat_id = "2147638491"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Dozmot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3c 5c 74 0b 3c 3a 74 07 83 ee 01 85 f6 7f ed}  //weight: 1, accuracy: High
        $x_1_2 = "=domo" ascii //weight: 1
        $x_1_3 = "/2PostMb.asp" ascii //weight: 1
        $x_1_4 = "163.com" ascii //weight: 1
        $x_1_5 = "360SE.exe" ascii //weight: 1
        $x_1_6 = "wowinfo.ini" ascii //weight: 1
        $x_1_7 = "wow.exe" ascii //weight: 1
        $x_1_8 = "SecurityMatrixKeypadButtonOK" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

