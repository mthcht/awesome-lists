rule TrojanSpy_Win32_Pophot_A_2147598355_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Pophot.A"
        threat_id = "2147598355"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Pophot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 03 43 c6 43 01 72 c6 43 02 65 c6 43 03 61 c6 43 04 74 c6 43 05 65 c6 43 06 44 c6 43 07 69 c6 43 08 72 c6 43 09 65 c6 43 0a 63 c6 43 0b 74 c6 43 0c 6f c6 43 0d 72 c6 43 0e 79 c6 43 0f 41 c6 43 10 00 53 8b 45 f8 50 e8 ?? ?? ?? ?? 8b d8 8d 45 e0 e8 ?? ?? ?? ?? 57 56 ff d3 83 f8 01 1b c0 40 88 45 ff 33 c0 5a 59 59}  //weight: 1, accuracy: Low
        $x_1_2 = {c6 03 46 c6 43 01 69 c6 43 02 6e c6 43 03 64 c6 43 04 57 c6 43 05 69 c6 43 06 6e c6 43 07 64 c6 43 08 6f c6 43 09 77 c6 43 0a 41 c6 43 0b 00}  //weight: 1, accuracy: High
        $x_1_3 = {c6 03 47 c6 43 01 65 c6 43 02 74 c6 43 03 57 c6 43 04 69 c6 43 05 6e c6 43 06 64 c6 43 07 6f c6 43 08 77 c6 43 09 54 c6 43 0a 68 c6 43 0b 72 c6 43 0c 65 c6 43 0d 61 c6 43 0e 64 c6 43 0f 50 c6 43 10 72 c6 43 11 6f c6 43 12 63 c6 43 13 65 c6 43 14 73 c6 43 15 73 c6 43 16 49 c6 43 17 64 c6 43 18 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Pophot_D_2147600416_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Pophot.D"
        threat_id = "2147600416"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Pophot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {50 b9 e8 03 00 00 ba 01 00 00 00 b8 ?? ?? ?? ?? e8 ?? ?? ff ff 8b 55 ?? b9 ?? ?? ?? ?? b8 02 00 00 80 e8 ?? ?? ff ff 8b 45 fc e8 ?? ?? ff ff 83 f8 0a 0f 8f ?? ?? 00 00 8d 45 ?? 50 b9 ?? ?? ?? ?? ba ?? ?? ?? ?? b8 02 00 00 80 e8 ?? ?? ff ff 8b 55 ?? 8d 45 fc b9 ?? ?? ?? ?? e8 ?? ?? ff ff 8b 45 fc 50}  //weight: 4, accuracy: Low
        $x_2_2 = {8b d8 8b 45 dc e8 ?? ?? ff ff 8d 45 e0 ba ?? ?? ?? ?? e8 ?? ?? ff ff 6a 64 e8 ?? ?? ff ff e8 ?? ?? ff ff 2b c3 3d 60 ea 00 00 0f 82 ?? ?? 00 00 e8 ?? ?? ff ff 2b c6 3d b8 0b 00 00}  //weight: 2, accuracy: Low
        $x_2_3 = {b9 e8 03 00 00 ba 01 00 00 00 b8 ?? ?? ?? ?? e8 ?? ?? ff ff 8d 45 b0 50 b9 64 00 00 00 ba 01 00 00 00 b8 ?? ?? ?? ?? e8 ?? ?? ff ff 8b 45 b0 50 8d 45 ac 50}  //weight: 2, accuracy: Low
        $x_1_4 = "AVP.Product_Notification" ascii //weight: 1
        $x_1_5 = "cj.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Pophot_F_2147601066_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Pophot.F!dll"
        threat_id = "2147601066"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Pophot"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {50 b9 e8 03 00 00 ba 01 00 00 00 b8 ?? ?? ?? ?? e8 ?? ?? ff ff 8b 55 ?? b9 ?? ?? ?? ?? b8 02 00 00 80 e8 ?? ?? ff ff 8b 45 fc e8 ?? ?? ff ff 83 f8 0a 0f 8f ?? ?? 00 00 8d 45 ?? 50 8d 85 7c ff ff ff 50 b9 e8 03 00 00 ba 01 00 00 00 b8 ?? ?? ?? ?? e8 ?? ?? ff ff 8b 95 7c ff ff ff b9 ?? ?? ?? ?? b8 02 00 00 80 e8 ?? ?? ff ff}  //weight: 10, accuracy: Low
        $x_10_2 = {b9 e8 03 00 00 ba 01 00 00 00 b8 ?? ?? ?? ?? e8 ?? ?? ff ff 8d 45 b4 50 b9 64 00 00 00 ba 01 00 00 00 b8 ?? ?? ?? ?? e8 ?? ?? ff ff 8b 55 b4}  //weight: 10, accuracy: Low
        $x_1_3 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_4 = "zuoyue16.ini" ascii //weight: 1
        $x_1_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\run" ascii //weight: 1
        $x_1_6 = "AVP.TrafficMonConnectionTerm" ascii //weight: 1
        $x_1_7 = "AVP.Product_Notification" ascii //weight: 1
        $x_1_8 = "cj.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Pophot_G_2147601102_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Pophot.G"
        threat_id = "2147601102"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Pophot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "61"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "zuoyue16.ini" ascii //weight: 1
        $x_1_2 = "s.ini" ascii //weight: 1
        $x_10_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\run" ascii //weight: 10
        $x_10_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders" ascii //weight: 10
        $x_10_5 = "AVP.A" ascii //weight: 10
        $x_10_6 = "AVP.Product_Notification" ascii //weight: 10
        $x_10_7 = "AVP.TrafficMonConnectionTerm" ascii //weight: 10
        $x_10_8 = ".lnk" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Pophot_H_2147601263_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Pophot.H"
        threat_id = "2147601263"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Pophot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 63 31 36 2e 69 6e 69 00 00 00 00 ff ff ff ff 07 00 00 00 53 74 61 72 74 75 70 00 ff ff ff ff 40 00 00 00 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 20 46 6f 6c 64 65 72 73}  //weight: 1, accuracy: High
        $x_1_2 = "c:\\nmDelm.bat" ascii //weight: 1
        $x_1_3 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 6d 79 63 63 30 38 30 [0-3] 2e 64 6c 6c 20 6d 79 6d 61 69 6e}  //weight: 1, accuracy: Low
        $x_1_4 = {7a 73 6d 73 63 63 00 00 ff ff ff ff 0b 00 00 00 5c 75 70 64 61 74 65 2e 65 78 65 00 ff ff ff ff 07 00 00 00 6d 79 63 63 33 32 2e 00 ff ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Pophot_H_2147601264_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Pophot.H!dll"
        threat_id = "2147601264"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Pophot"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_2 = {63 3a 5c 64 6f 77 6e 66 00 00 00 00 ff ff ff ff 04 00 00 00 2e 62 61 74 00 00 00 00 ff ff ff ff}  //weight: 1, accuracy: High
        $x_1_3 = {ff ff ff ff 02 00 00 00 64 6f 00 00 ff ff ff ff 04 00 00 00 6b 69 6c 6c 00 00 00 00 ff ff ff ff 01 00 00 00 30 00 00 00 ff ff ff ff 03 00 00 00 76 65 72 00 ff ff ff ff 06 00 00 00 6d 79 64 6f 77 6e}  //weight: 1, accuracy: High
        $x_1_4 = {8b d8 8b 45 f4 50 8d 45 bc 50 b9 ?? ?? ?? ?? ba ?? ?? ?? ?? b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 6a 02 e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 33 d2 52 50 8b c3 99}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Pophot_K_2147601792_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Pophot.K!dll"
        threat_id = "2147601792"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Pophot"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "34"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {64 6f 00 00 ff ff ff ff 04 00 00 00 6b 69 6c 6c 00 00 00 00 ff ff ff ff 04 00 00 00 6d 73 67 73 00 00 00 00 ff ff ff ff 03 00 00 00 73 79 73}  //weight: 10, accuracy: High
        $x_10_2 = {72 75 6e 00 ff ff ff ff 03 00 00 00 6d 73 67 00 ff ff ff ff 03 00 00 00 76 65 72 00 ff ff ff ff 06 00 00 00 6d 79 64 6f 77 6e}  //weight: 10, accuracy: High
        $x_10_3 = "dfzhqb.exe" ascii //weight: 10
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders" ascii //weight: 1
        $x_1_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\run" ascii //weight: 1
        $x_1_6 = "Startup" ascii //weight: 1
        $x_1_7 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Pophot_K_2147602104_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Pophot.K"
        threat_id = "2147602104"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Pophot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6a 00 6a 00 49 75 f9 53 56 57 8b f2 89 45 fc 8b 45 fc e8 ?? ?? ?? ?? 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 8d 45 f0 e8 ?? ?? ?? ?? 8b 45 fc e8 ?? ?? ?? ?? 8b d8 d1 fb 79 03 83 d3 00 85 db 7e 48 bf 01 00 00 00 56 8b d7 03 d2 4a b9 02 00 00 00 8b 45 fc e8}  //weight: 10, accuracy: Low
        $x_1_2 = {68 74 74 70 3a 2f 2f [0-15] 2e 63 6e}  //weight: 1, accuracy: Low
        $x_1_3 = "GET //yy.txt HTTP/1.1" ascii //weight: 1
        $x_1_4 = {76 65 72 3d [0-5] 26 74 67 69 64 3d [0-10] 26 61 64 64 72 65 73 73 3d [0-2] 2d}  //weight: 1, accuracy: Low
        $x_1_5 = "dll_hitpop" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Pophot_K_2147602104_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Pophot.K"
        threat_id = "2147602104"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Pophot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 20 46 6f 6c 64 65 72 73 00 00 00 00 ff ff ff ff 0e 00 00 00 43 6f 6d 6d 6f 6e 20 53 74 61 72 74 75 70 00 00 ff ff ff ff 0b 00 00 00 5c 6f 66 66 69 63 65 2e 6c 6e 6b 00 ff ff ff ff}  //weight: 1, accuracy: High
        $x_1_3 = {70 77 69 73 00 00 00 00 ff ff ff ff 06 00 00 00 79 73 2e 69 6e 69 00 00 ff ff ff ff}  //weight: 1, accuracy: High
        $x_1_4 = {6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 00 00 ff ff ff ff 10 00 00 00 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 00 00 00 00 ff ff ff ff 10 00 00 00 69 65 73 5c 45 78 70 6c 6f 72 65 72 5c 72 75 6e 00 00 00 00 ff ff ff ff 0b 00 00 00 6d 79 77 65 68 69 74 2e 69 6e 69 00 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

