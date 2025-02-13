rule Virus_Win32_Otwycal_A_2147606371_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Otwycal.gen!A"
        threat_id = "2147606371"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Otwycal"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "h.exthdowsh\\win" ascii //weight: 10
        $x_10_2 = "C:\\WINDOWS\\windows.ext" ascii //weight: 10
        $x_10_3 = "E0hxec" ascii //weight: 10
        $x_10_4 = "horyAhrecthwsDihindohGetW" ascii //weight: 10
        $x_10_5 = {4d 5a 4b 45 52 4e 45 4c 33 32 2e 44 4c 4c 00 00 50 45 00 00 4c 01 03 00 be b0 11 15 13 ad 50 ff 76 34 eb 7c 48 01 0f 01 0b 01 4c 6f 61 64 4c 69 62 72 61 72 79 41 00 00 18 10 00 00 10 00 00 00}  //weight: 10, accuracy: High
        $x_1_6 = {5d 59 46 ad 85 c0 74 1f 51 56 97 ff d1 93 ac 84 c0 75 fb 38 06 74 ea 8b c6 79 05 46 33 c0 66 ad 50 53 ff d5 ab eb e7 c3 00 50 0e 00 00 10 00 00 f0 01 00 00 10 00 00 00 60 60 23 13 ef 94 23 13 62 00 00 00 60 00 00 e0 00 10 15 13 24 95 23 13 00 b0 00 00 00 60 0e 00 4c 36 00 00 00 02 00 00 e0 4b 15 13 ff 4f 23 13 4c 96 23 13 60 00 00 e0}  //weight: 1, accuracy: High
        $x_1_7 = {50 53 ff d5 ab eb e7 c3 00 50 0e 00 00 10 00 00 f0 01 00 00 10 00 00 00 60 60 23 13 73 95 23 13 5f 00 00 00 60 00 00 e0 00 10 15 13 a8 95 23 13 00 b0 00 00 00 60 0e 00 d0 36 00 00 00 02 00 00 90 4c 15 13 ff 4f 23 13 d0 96 23 13 60 00 00 e0 69 55 23 13 fc 0f 15 13 00 10 00 00 00 10 0f 00 f0 01 00 00 10 00 00 00 40 95 23 13 43 95 23 13}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Virus_Win32_Otwycal_B_2147606738_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Otwycal.gen!B"
        threat_id = "2147606738"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Otwycal"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 2c 01 00 00 ff 75 38 ff 55 10 6a 00 68 2e 65 78 74 68 64 6f 77 73 68 5c 77 69 6e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

