rule Ransom_Win32_Petya_A_2147710272_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Petya.A"
        threat_id = "2147710272"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Petya"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $n_100_1 = {00 50 65 74 79 61 45 78 74 72 61 63 74 6f 72 2e 65 78 65 00 54 4d 65 74 68 6f 64 49 6d 70 6c 65 6d 65 6e 74 61 74 69 6f 6e 49 6e 74 65 72 63 65 70 74 00}  //weight: -100, accuracy: High
        $x_2_2 = {e8 14 00 66 48 66 83 f8 00 75 f5 66 a1 00 80 ea 00 80 00 00 f4 eb fd}  //weight: 2, accuracy: High
        $x_2_3 = {89 e7 66 50 66 53 06 51 6a 01 6a 10 89 e6 8a 16 ?? 7c b4 42 cd 13}  //weight: 2, accuracy: Low
        $x_2_4 = {73 08 50 30 e4 cd 13 58 eb d6 66 83 c3 01 66 83 d0 00 81 c1 00 02 73 07}  //weight: 2, accuracy: High
        $x_1_5 = {b8 03 00 cd 10 b8 00 05 cd 10 b9 07 26 b4 01 cd 10}  //weight: 1, accuracy: High
        $x_1_6 = {8a 7e 04 33 c9 ba 4f 18 b8 00 06 cd 10 32 ff 33 d2 b4 02 cd 10}  //weight: 1, accuracy: High
        $x_1_7 = {66 c7 46 f6 00 00 00 00 8d 86 f0 fd 89 46 fc 81 7e ee 55 aa 74 03 e9}  //weight: 1, accuracy: High
        $x_1_8 = {68 48 9f e8 b4 fc 5b e8 3c 00 cd 19}  //weight: 1, accuracy: High
        $x_1_9 = {57 56 c6 46 ?? 78 c6 46 ?? 70 c6 46 ?? 61 c6 46 ?? 6e c6 46 ?? 64 c6 46 ?? 33 c6 46 ?? 32 c6 46 ?? 2d}  //weight: 1, accuracy: Low
        $x_1_10 = {7d 33 8d 41 0b 6b c0 14 c7 04 30 3d 5f 3c 00}  //weight: 1, accuracy: High
        $x_2_11 = {68 00 00 10 80 51 ff 15 ?? ?? ?? ?? 83 f8 ff 75 0c 50 ff 15 ?? ?? ?? ?? 6a 02 58 eb 2d 56 8d 4d fc 51 68 90 00 00 00 8d 8d ?? ff ff ff 51 56 56 68 48 00 07 00}  //weight: 2, accuracy: Low
        $x_2_12 = {68 00 44 00 00 56 ff 15 ?? ?? ?? ?? 57 8d 44 24 14 50 53 8d 85 00 02 00 00}  //weight: 2, accuracy: Low
        $x_1_13 = {8d 4d f8 51 6a 06 56 56 56 68 50 03 00 c0 ff d0}  //weight: 1, accuracy: High
        $x_1_14 = "You became victim of the PETYA RANSOMWARE!" ascii //weight: 1
        $x_1_15 = "CHKDSK is repairing sector" ascii //weight: 1
        $x_1_16 = "You can purchase this key on the darknet page" ascii //weight: 1
        $x_1_17 = "://petya" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Petya_A_2147710507_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Petya.A!!Petya.gen!A"
        threat_id = "2147710507"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Petya"
        severity = "Critical"
        info = "Petya: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $n_100_1 = {00 50 65 74 79 61 45 78 74 72 61 63 74 6f 72 2e 65 78 65 00 54 4d 65 74 68 6f 64 49 6d 70 6c 65 6d 65 6e 74 61 74 69 6f 6e 49 6e 74 65 72 63 65 70 74 00}  //weight: -100, accuracy: High
        $x_2_2 = {e8 14 00 66 48 66 83 f8 00 75 f5 66 a1 00 80 ea 00 80 00 00 f4 eb fd}  //weight: 2, accuracy: High
        $x_2_3 = {89 e7 66 50 66 53 06 51 6a 01 6a 10 89 e6 8a 16 ?? 7c b4 42 cd 13}  //weight: 2, accuracy: Low
        $x_2_4 = {73 08 50 30 e4 cd 13 58 eb d6 66 83 c3 01 66 83 d0 00 81 c1 00 02 73 07}  //weight: 2, accuracy: High
        $x_1_5 = {b8 03 00 cd 10 b8 00 05 cd 10 b9 07 26 b4 01 cd 10}  //weight: 1, accuracy: High
        $x_1_6 = {8a 7e 04 33 c9 ba 4f 18 b8 00 06 cd 10 32 ff 33 d2 b4 02 cd 10}  //weight: 1, accuracy: High
        $x_1_7 = {66 c7 46 f6 00 00 00 00 8d 86 f0 fd 89 46 fc 81 7e ee 55 aa 74 03 e9}  //weight: 1, accuracy: High
        $x_1_8 = {68 48 9f e8 b4 fc 5b e8 3c 00 cd 19}  //weight: 1, accuracy: High
        $x_1_9 = {57 56 c6 46 ?? 78 c6 46 ?? 70 c6 46 ?? 61 c6 46 ?? 6e c6 46 ?? 64 c6 46 ?? 33 c6 46 ?? 32 c6 46 ?? 2d}  //weight: 1, accuracy: Low
        $x_1_10 = {7d 33 8d 41 0b 6b c0 14 c7 04 30 3d 5f 3c 00}  //weight: 1, accuracy: High
        $x_2_11 = {68 00 00 10 80 51 ff 15 ?? ?? ?? ?? 83 f8 ff 75 0c 50 ff 15 ?? ?? ?? ?? 6a 02 58 eb 2d 56 8d 4d fc 51 68 90 00 00 00 8d 8d ?? ff ff ff 51 56 56 68 48 00 07 00}  //weight: 2, accuracy: Low
        $x_2_12 = {68 00 44 00 00 56 ff 15 ?? ?? ?? ?? 57 8d 44 24 14 50 53 8d 85 00 02 00 00}  //weight: 2, accuracy: Low
        $x_1_13 = {8d 4d f8 51 6a 06 56 56 56 68 50 03 00 c0 ff d0}  //weight: 1, accuracy: High
        $x_1_14 = "You became victim of the PETYA RANSOMWARE!" ascii //weight: 1
        $x_1_15 = "CHKDSK is repairing sector" ascii //weight: 1
        $x_1_16 = "You can purchase this key on the darknet page" ascii //weight: 1
        $x_1_17 = "://petya" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Petya_B_2147722419_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Petya.B!rsm"
        threat_id = "2147722419"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Petya"
        severity = "Critical"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {31 4d 7a 37 31 35 33 48 4d 75 78 58 54 75 52 32 52 31 74 37 38 6d 47 53 64 7a 61 41 74 4e 62 42 57 58 00}  //weight: 4, accuracy: High
        $x_1_2 = "\\\\.\\PhysicalDrive" ascii //weight: 1
        $x_1_3 = {59 00 6f 00 75 00 72 00 20 00 70 00 65 00 72 00 73 00 6f 00 6e 00 61 00 6c 00 20 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 61 00 74 00 69 00 6f 00 6e 00 20 00 6b 00 65 00 79 00 3a 00 0d 00}  //weight: 1, accuracy: High
        $x_2_4 = ".asp.aspx.avhd.back.bak.c.cfg.conf.cpp.cs.ctl.db" wide //weight: 2
        $x_2_5 = {25 00 73 00 20 00 2f 00 6e 00 6f 00 64 00 65 00 3a 00 22 00 25 00 77 00 73 00 22 00 20 00 2f 00 75 00 73 00 65 00 72 00 3a 00 22 00 25 00 77 00 73 00 22 00 20 00 2f 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 3a 00 22 00 25 00 77 00 73 00 22 00 20 00 00 00 70 00 72 00 6f 00 63 00}  //weight: 2, accuracy: High
        $x_2_6 = "fsutil usn deletejournal" wide //weight: 2
        $x_3_7 = "rundll32.exe \\\"C:\\Windows\\%s\\\" #1" wide //weight: 3
        $x_1_8 = {70 65 72 66 63 2e 64 61 74 00}  //weight: 1, accuracy: High
        $x_2_9 = {53 00 59 00 53 00 54 00 45 00 4d 00 22 00 20 00 00 00 00 00 00 00 64 00 6c 00 6c 00 68 00 6f 00 73 00 74 00 2e 00 64 00 61 00 74 00 00 00 6e 74}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Petya_B_2147722420_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Petya.B!rsm!!Petya.gen!B"
        threat_id = "2147722420"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Petya"
        severity = "Critical"
        info = "rsm: an internal category used to refer to some threats"
        info = "Petya: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "B: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {31 4d 7a 37 31 35 33 48 4d 75 78 58 54 75 52 32 52 31 74 37 38 6d 47 53 64 7a 61 41 74 4e 62 42 57 58 00}  //weight: 4, accuracy: High
        $x_1_2 = "\\\\.\\PhysicalDrive" ascii //weight: 1
        $x_1_3 = {59 00 6f 00 75 00 72 00 20 00 70 00 65 00 72 00 73 00 6f 00 6e 00 61 00 6c 00 20 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 61 00 74 00 69 00 6f 00 6e 00 20 00 6b 00 65 00 79 00 3a 00 0d 00}  //weight: 1, accuracy: High
        $x_2_4 = ".asp.aspx.avhd.back.bak.c.cfg.conf.cpp.cs.ctl.db" wide //weight: 2
        $x_2_5 = {25 00 73 00 20 00 2f 00 6e 00 6f 00 64 00 65 00 3a 00 22 00 25 00 77 00 73 00 22 00 20 00 2f 00 75 00 73 00 65 00 72 00 3a 00 22 00 25 00 77 00 73 00 22 00 20 00 2f 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 3a 00 22 00 25 00 77 00 73 00 22 00 20 00 00 00 70 00 72 00 6f 00 63 00}  //weight: 2, accuracy: High
        $x_2_6 = "fsutil usn deletejournal" wide //weight: 2
        $x_3_7 = "rundll32.exe \\\"C:\\Windows\\%s\\\" #1" wide //weight: 3
        $x_1_8 = {70 65 72 66 63 2e 64 61 74 00}  //weight: 1, accuracy: High
        $x_2_9 = {53 00 59 00 53 00 54 00 45 00 4d 00 22 00 20 00 00 00 00 00 00 00 64 00 6c 00 6c 00 68 00 6f 00 73 00 74 00 2e 00 64 00 61 00 74 00 00 00 6e 74}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Petya_C_2147723923_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Petya.C"
        threat_id = "2147723923"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Petya"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "You became victim of the GOLDENEYE RANSOMWARE!" ascii //weight: 1
        $x_1_2 = "You can purchase this key on the darknet page shown" ascii //weight: 1
        $x_1_3 = "To purchase your key and restore your data, please follow these three easy steps:" ascii //weight: 1
        $x_1_4 = "Enter your personal decryption code there:" ascii //weight: 1
        $x_2_5 = {73 72 77 03 70 65 66 03 72 61 66 03 6f 72 66 03}  //weight: 2, accuracy: High
        $x_2_6 = {77 6d 61 03 77 6d 76 03 6f 67 67 03 73 77 66 24}  //weight: 2, accuracy: High
        $x_2_7 = {08 23 23 55 52 4c 31 23 23 08 23 23 55 52 4c 32 23 23 08 23 23 43 4f 44 45 23 23}  //weight: 2, accuracy: High
        $x_2_8 = "%s\\System32\\kernel32.dll:12345678" ascii //weight: 2
        $x_2_9 = "%s\\system32\\%c*%c.exe" ascii //weight: 2
        $x_1_10 = "%s\\system32\\%s" ascii //weight: 1
        $x_1_11 = "%s\\{%s}" ascii //weight: 1
        $x_1_12 = "://golden" ascii //weight: 1
        $x_1_13 = "://ipinfo.io/ip" ascii //weight: 1
        $x_1_14 = "SELECT * FROM AntivirusProduct" ascii //weight: 1
        $x_1_15 = "ROOT\\SecurityCenter2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Petya_C_2147723924_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Petya.C!!Petya.gen!A"
        threat_id = "2147723924"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Petya"
        severity = "Critical"
        info = "Petya: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "You became victim of the GOLDENEYE RANSOMWARE!" ascii //weight: 1
        $x_1_2 = "You can purchase this key on the darknet page shown" ascii //weight: 1
        $x_1_3 = "To purchase your key and restore your data, please follow these three easy steps:" ascii //weight: 1
        $x_1_4 = "Enter your personal decryption code there:" ascii //weight: 1
        $x_2_5 = {73 72 77 03 70 65 66 03 72 61 66 03 6f 72 66 03}  //weight: 2, accuracy: High
        $x_2_6 = {77 6d 61 03 77 6d 76 03 6f 67 67 03 73 77 66 24}  //weight: 2, accuracy: High
        $x_2_7 = {08 23 23 55 52 4c 31 23 23 08 23 23 55 52 4c 32 23 23 08 23 23 43 4f 44 45 23 23}  //weight: 2, accuracy: High
        $x_2_8 = "%s\\System32\\kernel32.dll:12345678" ascii //weight: 2
        $x_2_9 = "%s\\system32\\%c*%c.exe" ascii //weight: 2
        $x_1_10 = "%s\\system32\\%s" ascii //weight: 1
        $x_1_11 = "%s\\{%s}" ascii //weight: 1
        $x_1_12 = "://golden" ascii //weight: 1
        $x_1_13 = "://ipinfo.io/ip" ascii //weight: 1
        $x_1_14 = "SELECT * FROM AntivirusProduct" ascii //weight: 1
        $x_1_15 = "ROOT\\SecurityCenter2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Petya_PGP_2147936336_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Petya.PGP!MTB"
        threat_id = "2147936336"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Petya"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "petya37h5tbhyvki.onion/" ascii //weight: 1
        $x_4_2 = "petya5koahtsf7sv.onion/" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Petya_BA_2147941997_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Petya.BA!MTB"
        threat_id = "2147941997"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Petya"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "RANSOMWARE!" ascii //weight: 1
        $x_1_2 = "encryption algorithm." ascii //weight: 1
        $x_1_3 = "Tor Browser" ascii //weight: 1
        $x_1_4 = "access onion page" ascii //weight: 1
        $x_1_5 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-18] 2e 00 6f 00 6e 00 69 00 6f 00 6e 00 2f 00}  //weight: 1, accuracy: Low
        $x_1_6 = {68 74 74 70 3a 2f 2f [0-18] 2e 6f 6e 69 6f 6e 2f}  //weight: 1, accuracy: Low
        $x_1_7 = "decryption code" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

