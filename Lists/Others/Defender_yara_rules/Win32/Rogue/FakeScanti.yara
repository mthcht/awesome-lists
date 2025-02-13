rule Rogue_Win32_FakeScanti_138020_0
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeScanti"
        threat_id = "138020"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeScanti"
        severity = "102"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BlueFlare Antivirus" ascii //weight: 1
        $x_1_2 = "Running of application is impossible" ascii //weight: 1
        $x_1_3 = "action.php?p=%d&id=%s&system=%s&hwid=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeScanti_138020_1
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeScanti"
        threat_id = "138020"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeScanti"
        severity = "102"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ADC PlugIn" ascii //weight: 1
        $x_1_2 = {7b 37 37 44 43 30 42 61 61 2d 33 32 33 35 2d 34 62 61 39 2d 38 42 45 38 2d 61 61 39 45 42 36 37 38 46 41 30 32 7d 00}  //weight: 1, accuracy: High
        $x_1_3 = {53 65 72 69 61 6c 20 6b 65 79 20 61 63 63 65 70 74 65 64 2e 0d 0a 59 6f 75 20 6d 75 73 74 20 72 65 73 74 61 72 74 20 61 70 70 6c 69 63 61 74 69 6f 6e 2e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeScanti_138020_2
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeScanti"
        threat_id = "138020"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeScanti"
        severity = "102"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Wireshark Antivirus" ascii //weight: 1
        $x_1_2 = "protectyourpc-11.com/cgi-bin/cycle_report25.cgi" ascii //weight: 1
        $x_1_3 = "Internet attack attempt detected:" ascii //weight: 1
        $x_1_4 = "Windows has found spy programs running on your computer!" ascii //weight: 1
        $x_1_5 = "6988405C-71C3-427c-975A-0398706E79EE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeScanti_138020_3
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeScanti"
        threat_id = "138020"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeScanti"
        severity = "102"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "id=%s&hwid=%s&p=%d&os=%s" ascii //weight: 1
        $x_1_2 = "Security Guard 201" ascii //weight: 1
        $x_1_3 = "Internet attack attempt detected:" ascii //weight: 1
        $x_1_4 = "Running of application is impossible." ascii //weight: 1
        $x_1_5 = "Windows has detected malicious programs running on your computer." ascii //weight: 1
        $x_1_6 = "Warning: Infection is Detected" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Rogue_Win32_FakeScanti_138020_4
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeScanti"
        threat_id = "138020"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeScanti"
        severity = "102"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "&hwid=%s&p=%d&os=%s" ascii //weight: 1
        $x_1_2 = "http://%s/r.php" ascii //weight: 1
        $x_1_3 = "http://%s/sp.php?adv=%s&who=S" ascii //weight: 1
        $x_1_4 = "Please activate your antivirus software." ascii //weight: 1
        $x_1_5 = "Internet attack attempt detected:" ascii //weight: 1
        $x_1_6 = "Invalid serial number" ascii //weight: 1
        $x_1_7 = "In order to prevent permanent loss of your information and credit card data theft please activate your antivirus software." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Rogue_Win32_FakeScanti_138020_5
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeScanti"
        threat_id = "138020"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeScanti"
        severity = "102"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 3a 00 0f 85 c1 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {83 e9 08 0f 85 ff 75 1c}  //weight: 1, accuracy: Low
        $x_3_3 = {81 78 02 ec eb 05 90 0f 85}  //weight: 3, accuracy: High
        $x_3_4 = {81 38 33 c0 c2 2c 0f 85}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeScanti_138020_6
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeScanti"
        threat_id = "138020"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeScanti"
        severity = "102"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 b8 00 00 40 00 50 45 00 00 75 22 66 81 b8 18 00 40 00 0b 01 75 17 83 b8 74 00 40 00 0e 76 0e 33 c9 39 88 e8 00 40 00 0f 95 c1}  //weight: 1, accuracy: High
        $x_1_2 = "orP eciloP swodniW" ascii //weight: 1
        $x_1_3 = "WDefend" ascii //weight: 1
        $x_1_4 = "UNPROTECTED" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeScanti_138020_7
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeScanti"
        threat_id = "138020"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeScanti"
        severity = "102"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {12 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 50 00 6f 00 6c 00 69 00 63 00 65 00 20 00 50 00 72 00 6f 00 12 00 41 00 6e 00 74 00 69 00 76 00 69 00 72 00 75 00 73 00 20 00 32 00 30 00 30 00 39 00 20 00 50 00 72 00 6f 00 ?? 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeScanti_138020_8
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeScanti"
        threat_id = "138020"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeScanti"
        severity = "102"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3c 58 74 0c 50 6a 01 8d 4c 24 ?? e8 07 00 0f b6 86}  //weight: 1, accuracy: Low
        $x_1_2 = {81 b8 00 00 40 00 50 45 00 00 75 22 66 81 b8 18 00 40 00 0b 01 75 17 83 b8 74 00 40 00 0e 76 0e 33 c9 39 88 e8 00 40 00 0f 95 c1}  //weight: 1, accuracy: High
        $x_2_3 = "dbsinit.exe" ascii //weight: 2
        $x_1_4 = "UNPROTECTED" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeScanti_138020_9
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeScanti"
        threat_id = "138020"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeScanti"
        severity = "102"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {00 48 49 47 48 20 52 49 53 43 21 00 00 4c 4f 57 20 52 49 53 43 21 00}  //weight: 4, accuracy: High
        $x_4_2 = {00 4c 4f 57 20 52 49 53 43 21 00 00 00 48 49 47 48 20 52 49 53 43 21 00}  //weight: 4, accuracy: High
        $x_4_3 = {00 20 70 61 69 6e 74 2e 65 78 65 00 00 20 77 61 62 2e 65 78 65 00}  //weight: 4, accuracy: High
        $x_1_4 = {70 70 70 34 2e 64 61 74 00}  //weight: 1, accuracy: High
        $x_1_5 = "svchast" ascii //weight: 1
        $x_1_6 = "Windows Police Pro" ascii //weight: 1
        $x_1_7 = "Windows Antivirus Pro" ascii //weight: 1
        $x_1_8 = "orP eciloP swodniW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeScanti_138020_10
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeScanti"
        threat_id = "138020"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeScanti"
        severity = "102"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 69 6e 53 74 61 30 5c 44 65 66 61 75 6c 74 00 57 44 65 66 65 6e 64 00}  //weight: 1, accuracy: High
        $x_1_2 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 50 00 6f 00 6c 00 69 00 63 00 65 00 20 00 50 00 72 00 6f 00 12 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 50 00 6f 00 6c 00 69 00 63 00 65 00 20 00 50 00 72 00 6f 00 25 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00}  //weight: 1, accuracy: High
        $x_1_3 = {68 88 13 00 00 6a 01 6a 00 6a 00 6a 02 e8 ?? ?? ?? ?? 83 c4 14 85 c0 74 d7 6a 00 6a 00 6a 01 6a 00 ff 15 ?? ?? 40 00 85 c0 a3 ?? ?? ?? ?? 74 c0 68 e8 03 00 00 6a 02 6a 00 6a 00 6a 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeScanti_138020_11
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeScanti"
        threat_id = "138020"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeScanti"
        severity = "102"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 47 3c 8b 44 38 50 6a 40 68 00 30 00 00 50 57 56 ff 15}  //weight: 10, accuracy: High
        $x_1_2 = {5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 00 00 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 00 00 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 00 00 00 69 65 78 70 6c 6f 72 65 2e 65 78 65 00 00 00 00 65 78 70 6c 6f 72 65 72 2e 65 78 65 00 00 00 00 64 77 6d 2e 65 78 65 00 75 72 6c 6d 6f 6e 2e 64 6c 6c 00 00 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 00}  //weight: 1, accuracy: High
        $x_1_3 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 00 00 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 00 00 00 00 69 65 78 70 6c 6f 72 65 2e 65 78 65 00 00 00 00 65 78 70 6c 6f 72 65 72 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeScanti_138020_12
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeScanti"
        threat_id = "138020"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeScanti"
        severity = "102"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "<p class=\"h1\">DANGER!!!</p>" ascii //weight: 1
        $x_1_2 = "<p class=\"h2\">Your computer is INFECTED!</p>" ascii //weight: 1
        $x_1_3 = {3c 70 3e 53 75 63 68 06 00 69 6e 66 65 63 74 69 6f 6e 20 77 69 6c 6c 20 63 61 75 73 65 20 70 65 72 6d 61 6e 65 6e 74 20 6c 6f 73 73 20 6f 66 20 61 6c 6c 20 69 6e 66 6f 72 6d 61 74 69 6f 6e 20 73 74 6f 72 65 64 20 6f 6e 20 79 6f 75 72 20 63 6f 6d 70 75 74 65 72 3a}  //weight: 1, accuracy: Low
        $x_1_4 = "SPYWARE FROM YOUR COMPUTER RIGHT NOW!</p></td>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Rogue_Win32_FakeScanti_138020_13
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeScanti"
        threat_id = "138020"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeScanti"
        severity = "102"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 73 65 74 74 69 6e 67 73 2e 78 6d 6c 00 [0-4] 71 75 61 72 61 6e 74 69 6e 65 2e 78 6d 6c 00 [0-4] 69 67 6e 6f 72 65 2e 78 6d 6c 00}  //weight: 1, accuracy: Low
        $x_1_2 = {00 41 53 43 41 6e 74 69 73 70 79 77 61 72 65 44 6c 67 49 6e 69 74 69 61 6c 69 7a 65 64 45 76 65 6e 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 41 53 43 41 6e 74 69 73 70 79 77 61 72 65 41 6c 72 65 61 64 79 52 75 6e 4d 75 74 65 78 00}  //weight: 1, accuracy: High
        $x_1_4 = {65 6e 73 69 6f 6e 73 5c 7b 34 37 45 37 37 35 46 36 2d 32 32 43 43 2d 34 38 61 31 2d 38 37 34 36 2d 45 31 41 32 32 43 44 44 41 37 42 35 7d 00}  //weight: 1, accuracy: High
        $x_1_5 = {2f 63 6f 6e 74 65 78 74 00 [0-4] 2f 73 63 68 65 64 75 6c 65 64 00 [0-4] 2f 6d 69 6e 00 [0-4] 2f 75 6e 69 6e 73 74 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Rogue_Win32_FakeScanti_138020_14
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeScanti"
        threat_id = "138020"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeScanti"
        severity = "102"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 7b 25 64 35 44 39 45 34 45 30 2d 39 30 36 43 2d 34 42 38 31 2d 42 31 42 46 2d 32 45 39 41 37 36 32 34 38 31 34 36 7d 5f 25 64 00}  //weight: 2, accuracy: High
        $x_2_2 = {00 31 43 38 35 2d 34 33 42 34 2d 42 41 45 44 2d 39 32 32 45 45 36 36 37 32 34 46 36 00}  //weight: 2, accuracy: High
        $x_2_3 = {68 74 74 70 3a 2f 2f 25 73 2f 69 6e 64 65 78 2e 70 68 70 3f 64 72 6c 73 3d 38 37 26 69 64 3d 25 73 26 68 77 69 64 3d 25 73 00}  //weight: 2, accuracy: High
        $x_2_4 = {5c 67 62 5f 25 64 2e 62 61 74 00}  //weight: 2, accuracy: High
        $x_2_5 = {40 65 63 68 6f 20 6f 66 66 0d 0a 3a 61 0d 0a 64 65 6c 20 22 25 73 22 0d 0a 69 66 20 65 78 69 73 74 20 22 25 73 22 20 67 6f 74 6f 20 61 0d 0a 64 65 6c 20 25 25 30 0d 0a 00}  //weight: 2, accuracy: High
        $x_3_6 = {53 56 6a 10 33 db 6a 01 53 89 5d e0 c7 45 e4 50 00 72 00 c7 45 e8 69 00 76 00 c7 45 ec 61 00 74 00 c7 45 f0 65 00 42 00 c7 45 f4 75 00 69 00 c7 45 f8 6c 00 64 00 ff 15 ?? ?? ?? 00 8b f0 3b f3}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeScanti_138020_15
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeScanti"
        threat_id = "138020"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeScanti"
        severity = "102"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "id=%s&system=%s&mx=11&hwid=%s&n=%s" ascii //weight: 1
        $x_1_2 = "AV Guard Online" ascii //weight: 1
        $x_1_3 = "Running of application is impossible." ascii //weight: 1
        $x_1_4 = "Windows has detected malicious programs running on your computer." ascii //weight: 1
        $x_1_5 = "Your computer continues to be infected with harmful viruses." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeScanti_138020_16
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeScanti"
        threat_id = "138020"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeScanti"
        severity = "102"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {74 64 53 6a 00 6a 00 68 ?? ?? ?? ?? 56 ff 15 ?? ?? ?? ?? 8b 1d ?? ?? ?? ?? 6a 00 8d 44 24 ?? 50 6a 04 8d 4c 24 ?? 51 56 ff d3}  //weight: 2, accuracy: Low
        $x_2_2 = {74 4a 53 53 68 ?? ?? ?? ?? 56 ff 15 ?? ?? ?? ?? 53 8d 45 ?? 50 6a 04 8d 45 ?? 50 56 8b 35 ?? ?? ?? ?? ff d6}  //weight: 2, accuracy: Low
        $x_2_3 = {74 48 6a 02 53 6a 08 56 ff 15 ?? ?? ?? ?? 53 8d 45 ?? 50 6a 04 8d 45 ?? 50 56 8b 35 ?? ?? ?? ?? ff d6}  //weight: 2, accuracy: Low
        $x_2_4 = {74 61 53 6a 02 6a 00 6a 08 56 ff 15 ?? ?? ?? ?? 8b 1d ?? ?? ?? ?? 6a 00 8d 44 24 ?? 50 6a 04 8d 4c 24 ?? 51 56 ff d3}  //weight: 2, accuracy: Low
        $x_1_5 = {2e 63 67 69 3f 70 3d ?? 26 61 3d 25 64}  //weight: 1, accuracy: Low
        $x_1_6 = {2e 63 67 69 3f 68 6f 73 74 3d 25 73 26 69 64 3d 25 64 00}  //weight: 1, accuracy: High
        $x_1_7 = ":id:%d:createfile:%d" ascii //weight: 1
        $x_1_8 = ":id:0:magic:%d" ascii //weight: 1
        $x_1_9 = ":id:%d:createprocess:%d" ascii //weight: 1
        $x_1_10 = "\\em_%d.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeScanti_138020_17
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeScanti"
        threat_id = "138020"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeScanti"
        severity = "102"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {52 53 54 41 56 32 30 31 ?? 5c 72 65 6c 65 61 73 65 5c 52 53 54 20 41 6e 74 69 76 69 72 75 73 20 32 30 31 ?? 2e 70 64 62}  //weight: 2, accuracy: Low
        $x_2_2 = "About RST Antivirus 201" wide //weight: 2
        $x_2_3 = {4f 00 6e 00 65 00 20 00 49 00 6e 00 73 00 74 00 61 00 6e 00 63 00 65 00 20 00 6f 00 66 00 20 00 52 00 53 00 54 00 20 00 41 00 6e 00 74 00 69 00 76 00 69 00 72 00 75 00 73 00 20 00 32 00 30 00 31 00 [0-6] 69 00 73 00 20 00 61 00 6c 00 72 00 65 00 61 00 64 00 79 00 20 00 72 00 75 00 6e 00 6e 00 69 00 6e 00 67 00 21 00}  //weight: 2, accuracy: Low
        $x_1_4 = "\\WinDefPro.dat" wide //weight: 1
        $x_1_5 = "File %s cannot be removed" wide //weight: 1
        $x_1_6 = "daily.cvd" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeScanti_138020_18
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeScanti"
        threat_id = "138020"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeScanti"
        severity = "102"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4c 24 0c 57 57 68 73 05 00 00 51 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {52 00 75 00 6e 00 6e 00 69 00 6e 00 67 00 20 00 6f 00 66 00 20 00 61 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 20 00 69 00 73 00 20 00 69 00 6d 00 70 00 6f 00 73 00 73 00 69 00 62 00 6c 00 65 00 2e 00 20 00 54 00 68 00 65 00 20 00 66 00 69 00 6c 00 65 00 20 00 25 00 73 00 20 00 69 00 73 00 20 00 69 00 6e 00 66 00 65 00 63 00 74 00 65 00 64 00 2e 00 0a 00}  //weight: 1, accuracy: High
        $x_1_3 = {72 65 6c 65 61 73 65 5c 77 72 61 70 70 65 72 65 78 2e 70 64 62 00}  //weight: 1, accuracy: High
        $x_1_4 = {20 00 20 00 20 00 20 00 20 00 20 00 57 00 61 00 72 00 6e 00 69 00 6e 00 67 00 3a 00 20 00 49 00 6e 00 66 00 65 00 63 00 74 00 69 00 6f 00 6e 00 20 00 69 00 73 00 20 00 44 00 65 00 74 00 65 00 63 00 74 00 65 00 64 00 0a 00}  //weight: 1, accuracy: High
        $x_1_5 = {63 00 72 00 69 00 74 00 69 00 63 00 61 00 6c 00 20 00 73 00 79 00 73 00 74 00 65 00 6d 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 6f 00 6e 00 20 00 79 00 6f 00 75 00 72 00 20 00 63 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 20 00 74 00 68 00 61 00 74 00 20 00 77 00 65 00 72 00 65 00 20 00 6d 00 6f 00 64 00 69 00 66 00 69 00 65 00 64 00 20 00 62 00 79 00 20 00 6d 00 61 00 6c 00 69 00 63 00 69 00 6f 00 75 00 73 00 20 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 2e 00 0a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Rogue_Win32_FakeScanti_138020_19
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeScanti"
        threat_id = "138020"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeScanti"
        severity = "102"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 b8 00 00 40 00 50 45 00 00 75 22 66 81 b8 18 00 40 00 0b 01 75 17 83 b8 74 00 40 00 0e 76 0e 33 c9 39 88 e8 00 40 00 0f 95 c1}  //weight: 1, accuracy: High
        $x_1_2 = {2e 63 67 69 3f 70 3d ?? 26 61 3d}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 63 67 69 3f 68 6f 73 74 3d (25 73|68 6f) 26 69 64 3d 00}  //weight: 1, accuracy: Low
        $x_1_4 = ":id:%d:createfile:%d" ascii //weight: 1
        $x_1_5 = ":id:0:magic:%d" ascii //weight: 1
        $x_1_6 = ":id:%d:createprocess:%d" ascii //weight: 1
        $x_1_7 = "\\em_%d.bat" ascii //weight: 1
        $x_3_8 = "d%=a&1=p?igc.3noitca/" ascii //weight: 3
        $x_2_9 = "d%=di&s%=tsoh?igc." ascii //weight: 2
        $x_2_10 = "d%:cigam:0:di:" ascii //weight: 2
        $x_1_11 = "tab.d%_me\\" ascii //weight: 1
        $x_2_12 = "d%:elifetaerc:d%:di:" ascii //weight: 2
        $x_1_13 = "orP eciloP swodniW" ascii //weight: 1
        $x_1_14 = "UNPROTECTED" ascii //weight: 1
        $x_1_15 = {3a 2f 2f 63 6f 72 65 04 00 2e}  //weight: 1, accuracy: Low
        $x_1_16 = {00 59 6f 75 72 20 50 43 20 50 72 6f 74 65 63 74 6f 72 00}  //weight: 1, accuracy: High
        $x_1_17 = "\\ypp_%d.bat" ascii //weight: 1
        $x_1_18 = {20 41 6e 74 69 76 69 72 75 73 20 32 30 02 00 20 50 72 6f}  //weight: 1, accuracy: Low
        $x_3_19 = {8b 47 3c 8b 44 38 50 6a 40 68 00 30 00 00 50 57 56 ff 15}  //weight: 3, accuracy: High
        $x_1_20 = "Sysint ltd." wide //weight: 1
        $x_1_21 = {20 41 6e 74 69 76 69 72 75 73 04 10 0d 0d 0d 16 00 53 79 73 69 6e 74 65 72 6e 61 6c 73 13 00 57 69 72 65 73 68 61 72 6b 13 00 4d 69 6c 65 73 74 6f 6e 65 13 00 42 6c 75 65 66 6c 61 72 65}  //weight: 1, accuracy: Low
        $x_1_22 = "\\drv_%d.bat" ascii //weight: 1
        $x_1_23 = "//core%s.%s/stget" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeScanti_138020_20
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeScanti"
        threat_id = "138020"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeScanti"
        severity = "102"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Click here to undo performed modifications and remove malicious software (Highly recommended)." ascii //weight: 1
        $x_1_2 = {52 75 6e 6e 69 6e 67 20 6f 66 20 61 70 70 6c 69 63 61 74 69 6f 6e 20 69 73 20 69 6d 70 6f 73 73 69 62 6c 65 2e 04 00 54 68 65 20 66 69 6c 65 20 25 73 20 69 73 20 69 6e 66 65 63 74 65 64 2e 0a}  //weight: 1, accuracy: Low
        $x_1_3 = ".detcefni si s% elif ehT .elbissopmi si noitacilppa fo gninnuR" ascii //weight: 1
        $x_1_4 = {20 20 20 20 20 20 57 61 72 6e 69 6e 67 3a 20 49 6e 66 65 63 74 69 6f 6e 20 69 73 20 44 65 74 65 63 74 65 64 0a}  //weight: 1, accuracy: High
        $x_1_5 = {63 72 69 74 69 63 61 6c 20 73 79 73 74 65 6d 20 66 69 6c 65 73 20 6f 6e 20 79 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 74 68 61 74 20 77 65 72 65 20 6d 6f 64 69 66 69 65 64 20 62 79 20 6d 61 6c 69 63 69 6f 75 73 20 70 72 6f 67 72 61 6d 2e 0a}  //weight: 1, accuracy: High
        $x_2_6 = {64 62 73 69 6e 69 74 2e 65 78 65 00 (57 69 6e 64 6f 77|69 65 78 70 6c 6f 72 65 2e 65 78)}  //weight: 2, accuracy: Low
        $x_2_7 = "exe.tinisbd" ascii //weight: 2
        $x_1_8 = "orP eciloP swodniW" ascii //weight: 1
        $x_1_9 = {00 59 6f 75 72 20 50 43 20 50 72 6f 74 65 63 74 6f 72 00}  //weight: 1, accuracy: High
        $x_1_10 = {00 5f 57 50 50 5f 54 45 52 4d 49 4e 41 54 45 00}  //weight: 1, accuracy: High
        $x_1_11 = {50 6c 65 61 73 65 20 61 63 74 69 76 61 74 65 20 79 6f 75 72 20 61 6e 74 69 76 69 72 75 73 20 (70 72 6f 67 72|73 6f 66 74 77 61) 2e}  //weight: 1, accuracy: Low
        $x_2_12 = {00 5f 73 79 73 67 75 61 72 64 31 00 00 5f 73 79 73 67 75 61 72 64 32 00}  //weight: 2, accuracy: High
        $x_1_13 = {64 65 6c 20 25 25 30 0d 0a 00 00 00 00 5c (79|65 6d) 5f 25 64 2e 62 61 74 00}  //weight: 1, accuracy: Low
        $x_1_14 = {20 41 6e 74 69 76 69 72 75 73 20 32 30 02 00 20 50 72 6f}  //weight: 1, accuracy: Low
        $x_2_15 = {00 30 31 2e 65 78 65 00 00 77 6f 72 64 2e 65 78 65 00 [0-3] 73 65 72 76 65 72 2e 65 78 65}  //weight: 2, accuracy: Low
        $x_1_16 = {5c 64 72 76 5f 25 64 2e 62 61 74 00}  //weight: 1, accuracy: High
        $x_1_17 = {54 68 65 20 66 69 6c 65 20 25 73 20 69 73 20 69 6e 66 65 63 74 65 64 2e 04 00 52 75 6e 6e 69 6e 67 20 6f 66 20 61 70 70 6c 69 63 61 74 69 6f 6e 20 69 73 20 69 6d 70 6f 73 73 69 62 6c 65 2e}  //weight: 1, accuracy: Low
        $x_1_18 = {20 41 6e 74 69 76 69 72 75 73 04 10 0d 0d 0d 16 00 53 79 73 69 6e 74 65 72 6e 61 6c 73 13 00 57 69 72 65 73 68 61 72 6b 13 00 4d 69 6c 65 73 74 6f 6e 65 13 00 42 6c 75 65 66 6c 61 72 65}  //weight: 1, accuracy: Low
        $x_1_19 = {5c 77 72 73 25 64 5f 33 32 2e 62 61 74 00}  //weight: 1, accuracy: High
        $x_1_20 = {5f 53 48 41 52 4b 5f 44 49 45 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeScanti_138020_21
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeScanti"
        threat_id = "138020"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeScanti"
        severity = "102"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 43 6f 6f 6b 69 65 3a 25 73 40 25 73 00 [0-4] 5c 5c 2e 5c 70 69 70 65 5c 63 6f 6f 6b 69 65 73 5f 6d 6f 6e 69 74 6f 72 00}  //weight: 1, accuracy: Low
        $x_1_2 = {00 49 43 51 53 79 73 20 28 49 45 20 50 6c 75 67 49 6e 29 00}  //weight: 1, accuracy: High
        $x_1_3 = {6c 70 65 72 20 4f 62 6a 65 63 74 73 5c 7b 46 35 34 41 46 37 44 45 2d 36 30 33 38 2d 34 30 32 36 2d 38 34 33 33 2d 43 43 33 30 45 33 46 31 37 32 31 32 7d 00}  //weight: 1, accuracy: High
        $x_1_4 = "removal feature is disabled. You may scan your PC to locate" wide //weight: 1
        $x_1_5 = {00 53 6f 66 74 77 61 72 65 5c 53 6f 66 74 69 6d 65 72 00 [0-4] 73 79 73 74 45 74 68 30 00}  //weight: 1, accuracy: Low
        $x_1_6 = {2f 73 69 67 6e 75 70 2e 63 67 69 3f 76 65 72 3d ?? 26 61 66 66 3d}  //weight: 1, accuracy: Low
        $x_2_7 = {3d 66 66 61 26 ?? 3d 72 65 76 3f 69 67 63 2e 70 75 6e 67 69 73 2f}  //weight: 2, accuracy: Low
        $x_1_8 = {00 61 63 74 69 76 61 74 65 2e 68 74 6d 6c 00 00 00 5c 73 6f 6d 65 2e 64 61 74 00}  //weight: 1, accuracy: High
        $x_2_9 = {00 41 44 43 20 50 6c 75 67 49 6e 00}  //weight: 2, accuracy: High
        $x_1_10 = ".validateyourorder.com" ascii //weight: 1
        $x_2_11 = "ASC-AntiSpyware IEPlugin module" wide //weight: 2
        $x_1_12 = "Phka://%V/OYOdhl.RCY?" ascii //weight: 1
        $x_1_13 = {49 45 50 6c 75 67 69 6e 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77}  //weight: 1, accuracy: High
        $x_1_14 = "lper Objects\\{77DC0Baa-" ascii //weight: 1
        $x_1_15 = {00 74 68 72 65 65 64 6f 6c 6c 61 72 62 69 6c 6c 79 61 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_16 = {79 6f 75 72 6f 72 64 65 72 6e 6f 77 2e 63 6f 6d 00}  //weight: 1, accuracy: High
        $x_1_17 = {53 65 72 69 61 6c 20 6b 65 79 20 61 63 63 65 70 74 65 64 2e 0d 0a 59 6f 75 20 73 68 6f 75 6c 64 20 72 65 73 74 61 72 74 20 61 70 70 6c 69 63 61 74 69 6f 6e 2e}  //weight: 1, accuracy: High
        $x_1_18 = {4c 69 63 65 6e 73 65 20 6b 65 79 20 76 61 6c 69 64 61 74 65 64 2e 0d 0a 50 6c 65 61 73 65 2c 20 72 65 73 74 61 72 74 20 61 70 70 6c 69 63 61 74 69 6f 6e 2e}  //weight: 1, accuracy: High
        $x_1_19 = {73 69 67 6e 69 66 69 63 61 6e 74 6f 74 68 65 72 00}  //weight: 1, accuracy: High
        $x_2_20 = {61 64 63 5f 77 33 32 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00}  //weight: 2, accuracy: High
        $x_1_21 = {73 69 67 6e 75 70 2e 70 68 70 3f 69 64 3d 25 73 26 73 79 73 74 65 6d 3d 25 73 26 68 77 69 64 3d 25 73 26 6e 3d 25 73 00}  //weight: 1, accuracy: High
        $x_1_22 = {63 61 72 64 6f 6e 6c 69 6e 65 2e 63 6f 6d 00}  //weight: 1, accuracy: High
        $x_1_23 = "%s/sig/?id=%s&system=%s&hwid=%s&n=%s" ascii //weight: 1
        $x_1_24 = "OpenCloud Security" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeScanti_138020_22
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeScanti"
        threat_id = "138020"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeScanti"
        severity = "102"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {b9 01 00 00 00 89 4d ?? 8b 7d ?? 33 c0 85 f6 74 2d 8d 53 ff 3b ca 77 22 3b c6 73 22 8b 75 ?? 8d 14 38 8a 14 1a 32 14 39 41 88 14 30 8b 75 ?? 8d 53 ff 40 3b ca 76 e1}  //weight: 20, accuracy: Low
        $x_20_2 = {50 00 72 00 c7 45 ?? 69 00 76 00 c7 45 ?? 61 00 74 00 (c7 45 ?? 65 00 42 00 c7 45 ?? 75 00 69 00 c7 45 ?? 6c 00|b3 65 (??|?? ??|?? ?? ??|?? ?? ?? ??|?? ?? ?? ?? ??|?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??|?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??) c7 45 ?? 00 42 00 75 c7 45 ?? 00 69 00 6c 66 c7 45 ??) ff 15}  //weight: 20, accuracy: Low
        $x_10_3 = {2e 70 68 70 3f 69 64 3d 25 73 26 68 77 69 64 3d 25 73 00}  //weight: 10, accuracy: High
        $x_10_4 = {2e 70 68 70 3f 64 72 6c 73 3d 03 00 26 69 64 3d 25 73 26 68 77 69 64 3d 25 73 00}  //weight: 10, accuracy: Low
        $x_10_5 = {49 4d 47 3a 25 64 20 54 72 6f 6a 61 6e 2e 56 42 53 2e 51 68 6f 73 74 0d 0a 57 68 65 6e 20 41 63 74 69 76 69 74 79 4b 65 79 2e}  //weight: 10, accuracy: High
        $x_10_6 = "RESTORES Windows after system fail" wide //weight: 10
        $x_10_7 = "sher, you can ublock" wide //weight: 10
        $x_10_8 = {2e 70 68 70 3f 64 65 3d 03 00 26 6f 73 3d 25 73 26 6c 6e 3d 01 00 26 69 64 3d 25 73 26 68 77 69 64 3d 25 73 26 76 65 72 3d}  //weight: 10, accuracy: Low
        $x_10_9 = "&os=%s&vl=msd&id=%s&hwid=%s&ver=" ascii //weight: 10
        $x_10_10 = {54 53 54 41 54 44 00 00 53 54 41 54 45 44 00}  //weight: 10, accuracy: High
        $x_10_11 = "RESTORES Windows after system crash" wide //weight: 10
        $x_10_12 = "%s/sp.php?adv=%s&who=S" ascii //weight: 10
        $x_10_13 = "RESTORES system failure" wide //weight: 10
        $x_10_14 = {54 53 54 45 4d 44 00 00 53 54 41 54 45 44 00}  //weight: 10, accuracy: High
        $x_10_15 = "RESTORES system crash" wide //weight: 10
        $x_1_16 = {62 69 6e 67 2e 63 6f 6d 0d 0a 03 00 2e 03 00 2e 03 00 2e 03 00 09}  //weight: 1, accuracy: Low
        $x_10_17 = "RESTORES system destroy" wide //weight: 10
        $x_10_18 = "IMG:%d Trojan-Spy.WIn32.Zbot.ikh" ascii //weight: 10
        $x_1_19 = {6c 69 76 65 2e 63 6f 6d 0d 0a 03 00 2e 03 00 2e 03 00 2e 03 00 09}  //weight: 1, accuracy: Low
        $x_1_20 = {6d 73 6e 2e 63 6f 6d 0d 0a 03 00 2e 03 00 2e 03 00 2e 03 00 09}  //weight: 1, accuracy: Low
        $x_1_21 = {6d 69 63 72 6f 73 6f 66 74 2e 63 6f 6d 0d 0a 03 00 2e 03 00 2e 03 00 2e 03 00 09}  //weight: 1, accuracy: Low
        $x_1_22 = {09 6c 69 76 65 2e 63 6f 6d 12 00 [0-8] 0d 0a 03 00 2e 03 00 2e 03 00 2e 03 00}  //weight: 1, accuracy: Low
        $x_1_23 = {00 57 72 69 74 65 46 69 6c 00}  //weight: 1, accuracy: High
        $x_10_24 = "RESTORES your presonal" wide //weight: 10
        $x_10_25 = "IMG:%d Virus-Spy.Win32" ascii //weight: 10
        $x_10_26 = "RESTORES your PC destroy" wide //weight: 10
        $x_10_27 = "IMG:%d Net-Worm-Spy.Win32" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            ((1 of ($x_20_*) and 1 of ($x_1_*))) or
            ((1 of ($x_20_*) and 1 of ($x_10_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeScanti_138020_23
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeScanti"
        threat_id = "138020"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeScanti"
        severity = "102"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "Somebody is truing to attack your PC:" ascii //weight: 2
        $x_6_2 = {64 65 73 6f 74 [0-1] 2e 65 78 65 00 25 73 20 22 25 25 31 22 20 25 25 2a 00 [0-4] 65 78 65 66 69 6c 65 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 00}  //weight: 6, accuracy: Low
        $x_6_3 = {65 78 65 66 69 6c 65 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 00 [0-3] 25 73 20 22 25 25 31 22 20 25 25 2a 00 [0-3] 5c 70 75 6d 70 2e 65 78 65}  //weight: 6, accuracy: Low
        $x_6_4 = {65 78 65 66 69 6c 65 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 00 [0-3] 2a 25 25 20 22 31 25 25 22 20 73 25 00 [0-3] 65 78 65 2e 70 6d 75 70 5c}  //weight: 6, accuracy: Low
        $x_6_5 = {5c 61 6c 67 67 75 69 2e 65 78 65 00 65 78 65 66 69 6c 65 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 00 [0-3] 25 73 20 22 25 25 31 22 20 25 25 2a 00}  //weight: 6, accuracy: Low
        $x_6_6 = {5c 61 6c 67 67 75 69 2e 65 78 65 00 25 73 20 22 25 25 31 22 20 25 25 2a 00 [0-3] 65 78 65 66 69 6c 65 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 00}  //weight: 6, accuracy: Low
        $x_6_7 = {5c 63 6f 6e 68 6f 73 74 2e 65 78 65 00 [0-3] 25 73 20 22 25 25 31 22 20 25 25 2a 00 [0-3] 65 78 65 66 69 6c 65 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 00}  //weight: 6, accuracy: Low
        $x_6_8 = {25 73 20 22 25 25 31 22 20 25 25 2a 00 [0-3] 65 78 65 66 69 6c 65 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 00 [0-3] 5c 63 6f 6e 68 6f 73 74 2e 65 78 65 00}  //weight: 6, accuracy: Low
        $x_2_9 = {2f 61 63 74 69 6f 6e 33 2e 63 67 69 3f 70 3d 33 26 61 3d 25 64 00}  //weight: 2, accuracy: High
        $x_2_10 = "d%=a&3=p?igc.3noitca/" ascii //weight: 2
        $x_2_11 = {00 48 49 47 48 20 52 49 53 43 21 00 00 4c 4f 57 20 52 49 53 43 21 00}  //weight: 2, accuracy: High
        $x_2_12 = {00 4c 4f 57 20 52 49 53 43 21 00 00 00 48 49 47 48 20 52 49 53 43 21 00}  //weight: 2, accuracy: High
        $x_2_13 = {00 53 6f 66 74 77 61 72 65 5c 53 6f 66 74 69 6d 65 72 00 [0-4] 73 79 73 74 65 6d 45 74 68 30 00}  //weight: 2, accuracy: Low
        $x_2_14 = {00 73 79 73 45 74 68 30 00 53 6f 66 74 77 61 72 65 5c 53 6f 66 74 69 6d 65 72 00}  //weight: 2, accuracy: High
        $x_1_15 = {50 6c 65 61 73 65 20 72 65 73 74 61 72 74 20 74 68 65 20 70 72 6f 67 72 61 6d 20 66 6f 72 20 73 75 63 63 65 73 73 66 75 6c 6c 20 72 65 67 69 73 74 72 61 74 69 6f 6e 2e 00}  //weight: 1, accuracy: High
        $x_1_16 = {00 25 73 3a 61 70 70 3a 69 64 3a 30 3a 73 69 7a 65 3a 25 64 0a 00}  //weight: 1, accuracy: High
        $x_1_17 = {00 49 6e 74 65 72 6e 65 74 20 61 74 74 61 63 6b 20 61 74 74 65 6d 70 74 20 64 65 74 65 63 74 65 64 3a 00}  //weight: 1, accuracy: High
        $x_1_18 = {6f 72 50 20 65 63 69 6c 6f 50 20 73 77 6f 64 6e 69 57 00}  //weight: 1, accuracy: High
        $x_1_19 = {45 6d 61 69 6c 2d 57 6f 72 6d 2e 57 69 6e 33 32 2e 4d 65 72 6f 6e 64 2e 61 00}  //weight: 1, accuracy: High
        $x_1_20 = {54 72 6f 6a 61 6e 2e 57 69 6e 33 32 2e 41 67 65 6e 74 2e 61 7a 73 79 00}  //weight: 1, accuracy: High
        $x_1_21 = {54 72 6f 6a 61 6e 2e 57 69 6e 33 32 2e 41 67 65 6e 74 32 2e 64 74 62 00}  //weight: 1, accuracy: High
        $x_1_22 = {54 72 6f 6a 61 6e 2d 44 6f 77 6e 6c 6f 61 64 65 72 2e 57 69 6e 33 32 2e 53 6d 61 6c 6c 2e 79 64 68 00}  //weight: 1, accuracy: High
        $x_1_23 = {54 72 6f 6a 61 6e 2d 44 6f 77 6e 6c 6f 61 64 65 72 2e 57 69 6e 33 32 2e 41 67 65 6e 74 2e 61 68 6f 65 00}  //weight: 1, accuracy: High
        $x_1_24 = {54 72 6f 6a 61 6e 2d 44 6f 77 6e 6c 6f 61 64 65 72 2e 4a 53 2e 41 67 65 6e 74 2e 63 72 68 00}  //weight: 1, accuracy: High
        $x_1_25 = {4e 65 74 2d 57 6f 72 6d 2e 57 69 6e 33 32 2e 4b 69 64 6f 2e 69 68 00}  //weight: 1, accuracy: High
        $x_2_26 = "re serios threats detected on you comp" wide //weight: 2
        $x_2_27 = "core%s.%s/stat/action3.cgi?p=%d&a=%s" ascii //weight: 2
        $x_1_28 = "Base Defenition v 1." ascii //weight: 1
        $x_2_29 = {00 64 62 73 69 6e 69 74 2e 65 78 65 00 77 69 73 70 65 78 2e 68 74 6d 6c 00}  //weight: 2, accuracy: High
        $x_1_30 = {5c 77 72 73 25 64 5f 33 32 2e 62 61 74 00}  //weight: 1, accuracy: High
        $x_1_31 = {5c 6c 69 62 33 32 25 64 2e 62 61 74 00}  //weight: 1, accuracy: High
        $x_2_32 = "will cause unstable work of your sys" wide //weight: 2
        $x_2_33 = "{6988405C-71C3-427c-975A-0398706E79EE}" ascii //weight: 2
        $x_2_34 = "_MSTONE_TER" ascii //weight: 2
        $x_3_35 = {5f 6d 73 74 61 00 00 00 5f 6d 73 74 62 00 00 00 2e 65 78 65 00 00 00 00 63 73 72 73 73 2e 65 78 65}  //weight: 3, accuracy: High
        $x_1_36 = {20 41 6e 74 69 76 69 72 75 73 06 10 0d 0d 0d 0b 0d 16 00 53 79 73 69 6e 74 65 72 6e 61 6c 73 13 00 57 69 72 65 73 68 61 72 6b 13 00 4d 69 6c 65 73 74 6f 6e 65 13 00 42 6c 75 65 46 6c 61 72 65 11 00 57 6f 6c 66 72 61 6d 13 00 4f 70 65 6e 43 6c 6f 75 64}  //weight: 1, accuracy: Low
        $x_2_37 = "core%s.%s/stat/action.php?p=%d&id=%s&system=%s&hwid=%s" ascii //weight: 2
        $x_2_38 = {54 68 65 20 66 69 6c 65 20 22 25 73 22 20 69 73 20 69 6e 66 65 63 74 65 64 2e 04 00 52 75 6e 6e 69 6e 67 20 6f 66 20 61 70 70 6c 69 63 61 74 69 6f 6e 20 69 73 20 69 6d 70 6f 73 73 69 62 6c 65 2e}  //weight: 2, accuracy: Low
        $x_2_39 = "Windows has found spy programs running on your computer!" ascii //weight: 2
        $x_2_40 = "publisher, you can ublock it." wide //weight: 2
        $x_3_41 = {00 2e 65 78 65 00 00 00 00 63 73 72 73 73 2e 65 78 65 00 00 00 65 78 65 63 00}  //weight: 3, accuracy: High
        $x_1_42 = {00 5f 5f 57 4c 46}  //weight: 1, accuracy: High
        $x_3_43 = {00 6f 70 65 6e 00 00 00 00 61 20 65 78 65 63 25 73 00}  //weight: 3, accuracy: High
        $x_2_44 = {69 6d 70 6f 73 73 69 62 6c 65 2e 0a 0a 50 6c 65 61 73 65 20 61 63 74 69 76 61 74 65 20 79 6f 75 72 20 61 6e 74 69 76 69 72 75 73 20 73 6f 66 74 77 61 72 65 2e}  //weight: 2, accuracy: High
        $x_1_45 = {5c 73 64 25 64 2e 62 61 74 00}  //weight: 1, accuracy: High
        $x_2_46 = "{F053D246-5CC9-46E9-9C51-723D87E9990B}" ascii //weight: 2
        $x_2_47 = {3a 2f 2f 25 73 2f 65 78 32 2e 70 68 70 00 00 00 68 74 74 70 3a 2f 2f 25 73 2f 65 78 31 2e 70 68 70}  //weight: 2, accuracy: High
        $x_3_48 = {2f 72 2e 70 68 70 3f 69 64 3d 25 73 26 (6f 73|73 79 73 74) 3d 25 73 26 68 77 69 64 3d 25 73 26 70 3d 25 64}  //weight: 3, accuracy: Low
        $x_2_49 = "C4F6929-B564-4652-922B-EE805D39179F" ascii //weight: 2
        $x_1_50 = "wf.conf" ascii //weight: 1
        $x_3_51 = {44 69 73 61 62 6c 65 41 6e 74 69 53 70 79 77 61 72 65 00 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 44 65 66 65 6e 64 65 72 00}  //weight: 3, accuracy: High
        $x_4_52 = {81 c3 e6 00 00 00 53 83 c7 6e 57 ff 15 ?? ?? ?? ?? 33 c0 6a 0a}  //weight: 4, accuracy: Low
        $x_3_53 = {6d 63 61 67 65 6e 74 2e 65 78 65 00 4d 69 63 72 6f 73 6f 66 74 20 53 65 63 75 72 69 74 79 20 43 6c 69 65 6e 74 00 00}  //weight: 3, accuracy: High
        $x_3_54 = "%s/r.php?os=%s&id=%s&hwid=%s&p=%d" ascii //weight: 3
        $x_3_55 = "%s/r.php?hwid=%s&p=%d&os=%s&id=%s" ascii //weight: 3
        $x_2_56 = {46 00 75 00 63 00 6b 00 20 00 62 00 6c 00 6f 00 6e 00 64 00 79 00 00 00}  //weight: 2, accuracy: High
        $x_3_57 = {45 58 31 44 4f 4e 45 00 45 58 32 44 4f 4e 45 00}  //weight: 3, accuracy: High
        $x_2_58 = {46 00 69 00 6e 00 64 00 20 00 62 00 6c 00 6f 00 6e 00 64 00 79 00 00 00}  //weight: 2, accuracy: High
        $x_3_59 = {25 73 2f 72 2e 70 68 70 3f 76 65 72 3d [0-2] 26 68 77 69 64 3d 25 73 26 70 3d 25 64 26 6f 73 3d 25 73 26 69 64 3d 25 73}  //weight: 3, accuracy: Low
        $x_1_60 = "Include objects in Virus Vault" ascii //weight: 1
        $x_3_61 = "%s/r.php?hwid=%s&p=%d&id=%s&os=%s&ver=" ascii //weight: 3
        $x_3_62 = "%s/r.php?id=%s&hwid=%s&p=%d&os=%s&ver=" ascii //weight: 3
        $x_1_63 = {5c 6f 63 25 64 5f 77 33 32 2e 62 61 74 00}  //weight: 1, accuracy: High
        $x_1_64 = "OpenCloud Security" ascii //weight: 1
        $x_2_65 = {25 73 2f 73 2e 70 68 70 3f 63 3d [0-3] 26 69 64 3d 25 73 00}  //weight: 2, accuracy: Low
        $x_3_66 = "%s/sig/?id=%s&system=%s&hwid=%s&n=%s" ascii //weight: 3
        $x_3_67 = {25 73 2f 72 2e 70 68 70 3f 76 65 72 3d [0-2] 26 69 64 3d 25 73 26 68 77 69 64 3d 25 73 26 70 3d 25 64 26 6f 73 3d 25 73}  //weight: 3, accuracy: Low
        $x_2_68 = "Open Cloud AV" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            ((1 of ($x_3_*) and 5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((2 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((3 of ($x_3_*))) or
            ((1 of ($x_4_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*))) or
            ((1 of ($x_6_*) and 2 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_3_*))) or
            ((1 of ($x_6_*) and 1 of ($x_4_*))) or
            ((2 of ($x_6_*))) or
            (all of ($x*))
        )
}

