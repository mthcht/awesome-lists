rule Virus_Win32_Ursnif_D_2147692239_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Ursnif.D"
        threat_id = "2147692239"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2b c7 89 47 10 8b 45 ec 50 8b d6 8d 4b 18 89 47 14 e8 10 01 00 00 8b 4d fc 8b 7d f8 8b 41 78 57 8b 4c 38 10 8b 44 38 1c c1 e1 02 2b c1 8b 44 38 04 03 c7 ff d0 68 00 80 00 00 6a 00 57 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {8b fa 8b df c1 eb 02 83 e7 03 8b f1 85 db 74 1d 8a 45 0c 8b 16 02 c3 0f b6 c8 8b 45 08 d3 ca 33 d0 2b d3 89 16 83 c6 04 4b 75 e5 eb 03}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Ursnif_A_2147692481_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Ursnif.gen!A"
        threat_id = "2147692481"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {44 3a 28 44 3b 4f 49 43 49 3b 47 41 3b 3b 3b 42 47 29 28 44 3b 4f 49 43 49 3b 47 41 3b 3b 3b 41 4e 29 28 41 3b 4f 49 43 49 3b 47 41 3b 3b 3b 41 55 29 28 41 3b 4f 49 43 49 3b 47 41 3b 3b 3b 42 41 29 00}  //weight: 5, accuracy: High
        $x_5_2 = {53 3a 28 4d 4c 3b 3b 4e 57 3b 3b 3b 4c 57 29 00}  //weight: 5, accuracy: High
        $x_5_3 = {25 00 30 00 38 00 78 00 25 00 30 00 34 00 78 00 25 00 30 00 34 00 78 00 25 00 30 00 32 00 78 00 25 00 30 00 32 00 78 00 25 00 30 00 32 00 78 00 25 00 30 00 32 00 78 00 25 00 30 00 32 00 78 00 25 00 30 00 32 00 78 00 25 00 30 00 32 00 78 00 25 00 30 00 32 00 78 00 00 00}  //weight: 5, accuracy: High
        $x_5_4 = {73 00 70 00 70 00 63 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 5, accuracy: High
        $x_1_5 = {6e 00 5c 00 2a 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {53 74 61 72 74 75 70 41 70 70 72 6f 76 65 64 5c 52 75 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Virus_Win32_Ursnif_A_2147692481_1
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Ursnif.gen!A"
        threat_id = "2147692481"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "attrib -r -s -h \"%s\"" ascii //weight: 1
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run" wide //weight: 1
        $x_1_3 = "Global\\%08x%04x%04x%02x%02x%02x%02x%02x%02x%02x%02x" wide //weight: 1
        $x_1_4 = {c7 44 24 1c 30 00 00 00 89 54 24 20 ff 15 ?? ?? ?? ?? 8d 4c 24 0c e8 ?? ?? ?? ?? 81 74 24 0c fc 58 85 cf 8d 54 24 0c 8d 4c 24 30 e8}  //weight: 1, accuracy: Low
        $x_1_5 = {8d 85 dc f3 ff ff 50 68 04 01 00 00 ff 15 ?? ?? ?? ?? 8d 85 e4 fd ff ff 50 6a 00 68 ?? ?? ?? ?? 8d 85 dc f3 ff ff 50 ff 15 ?? ?? ?? ?? 83 ff 01 75 07 ba ?? ?? ?? ?? eb 0a 83 ff 02 75 10 ba ?? ?? ?? ?? 8d 8d e4 fd ff ff e8 ?? ?? ?? ?? 33 c0 50 68 80 00 00 00 6a 02 50 50 8b f0 68 00 00 00 40 8d 85 e4 fd ff ff 50 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Ursnif_B_2147692484_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Ursnif.gen!B"
        threat_id = "2147692484"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 53 59 53 49 4e 46 4f 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 53 43 52 45 45 4e 53 48 4f 54 00}  //weight: 1, accuracy: High
        $x_1_3 = "/pki/mscorp/crl/MSIT" ascii //weight: 1
        $x_1_4 = "cmd /C \"driverquery.exe >> %s\"" wide //weight: 1
        $x_1_5 = "/script?u=" ascii //weight: 1
        $x_1_6 = {8b c3 2b c6 a9 fe ff ff ff 74 3f 56 ff 15 ?? ?? ?? ?? 83 f8 02 74 05 83 f8 04 75 13 8d 45 f0 50 ff 75 ec ff 75 08 51 56 8b cf e8 ?? ?? ?? ?? 8b 45 fc 8d 73 02 8d 9d ec fd ff ff 2b c6 6a 00 03 c3 5b d1 f8 85 c0 7f 9e eb 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Virus_Win32_Ursnif_F_2147692535_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Ursnif.F"
        threat_id = "2147692535"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 06 0f b6 c0 46 83 e8 33 74 20 83 e8 33 74 34 83 e8 4a 74 11 83 e8 08 75 12 8b 06 89 01 83 c1 04 83 c6 04 eb 06 8a 06 88 01 41 46 3b f3 75 d0}  //weight: 1, accuracy: High
        $x_1_2 = {8b fa 8b df c1 eb 02 83 e7 03 8b f1 85 db 74 1f 8a 44 24 14 8b 16 02 c3 0f b6 c8 8b 44 24 10 d3 ca 33 d0 2b d3 89 16 83 c6 04 4b 75 e3}  //weight: 1, accuracy: High
        $x_1_3 = {6a 48 8d b7 00 04 00 00 8b d6 8d 4d b0 e8 a8 03 00 00 51 ff 76 4c 8d 4d b0 ff 76 48 6a 48 5a e8 7e 00 00 00 8b 4d b0 8b 55 b4 8d 45 f8 50 8d 45 fc 81 c1 00 04 00 00 50 03 cf e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Ursnif_C_2147692817_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Ursnif.gen!C"
        threat_id = "2147692817"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {44 3a 28 44 3b 4f 49 43 49 3b 47 41 3b 3b 3b 42 47 29 28 44 3b 4f 49 43 49 3b 47 41 3b 3b 3b 41 4e 29 28 41 3b 4f 49 43 49 3b 47 41 3b 3b 3b 41 55 29 28 41 3b 4f 49 43 49 3b 47 41 3b 3b 3b 42 41 29 00}  //weight: 5, accuracy: High
        $x_5_2 = {53 3a 28 4d 4c 3b 3b 4e 57 3b 3b 3b 4c 57 29 00}  //weight: 5, accuracy: High
        $x_5_3 = {25 00 30 00 38 00 78 00 25 00 30 00 34 00 78 00 25 00 30 00 34 00 78 00 25 00 30 00 32 00 78 00 25 00 30 00 32 00 78 00 25 00 30 00 32 00 78 00 25 00 30 00 32 00 78 00 25 00 30 00 32 00 78 00 25 00 30 00 32 00 78 00 25 00 30 00 32 00 78 00 25 00 30 00 32 00 78 00 00 00}  //weight: 5, accuracy: High
        $x_5_4 = "attrib -r -s -h \"%s\"" ascii //weight: 5
        $x_5_5 = "minicheck: %s" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

