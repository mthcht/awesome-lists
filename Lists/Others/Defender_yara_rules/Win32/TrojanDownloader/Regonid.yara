rule TrojanDownloader_Win32_Regonid_A_2147642627_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Regonid.A"
        threat_id = "2147642627"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Regonid"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {76 03 83 c1 ?? 8b 55 ?? 8a 14 10 2a 55 ?? 8b 1e 2a d0 02 d1 88 14 18 40 3b c7 72 da}  //weight: 6, accuracy: Low
        $x_1_2 = {81 c6 d0 07 00 00 81 fe 40 77 1b 00 72 cd}  //weight: 1, accuracy: High
        $x_1_3 = {80 3a 09 00 3b ?? 7e}  //weight: 1, accuracy: Low
        $x_1_4 = {44 69 67 69 74 61 6c 50 72 6f 64 75 63 74 53 75 62 49 64 00 [0-32] 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 52 65 67 69 73 74 72 61 74 69 6f 6e 00 00 [0-32] 7b 25 30}  //weight: 1, accuracy: Low
        $x_1_5 = {49 6e 73 74 61 6c 6c 46 6c 61 67 49 6e 66 6f 00 [0-10] 52 65 67 69 73 74 72 61 74 69 6f 6e 49 44 00 [0-10] 6c 6c 4d 61 69 6e 5f 44 4c 4c 5f 50 52 4f 43 45 53 53 5f 41 54 54 41 43 48}  //weight: 1, accuracy: Low
        $x_1_6 = {8a 1c 16 2a 1c 08 41 88 1a a1 ?? ?? ?? ?? 3b 08 72 02 33 c9 42 ff 4d ?? 75 e3}  //weight: 1, accuracy: Low
        $x_1_7 = {48 4b 45 59 5f 4c 4f 43 41 4c 5f 4d 41 43 48 49 4e 45 5c 25 73 5c 25 73 [0-16] 52 65 67 69 73 74 72 61 74 69 6f 6e 49 44}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_6_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Regonid_B_2147648357_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Regonid.B"
        threat_id = "2147648357"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Regonid"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {76 29 8b d0 2b d1 03 55 14 83 fa 7e 76 03 83 c1 7e 8b 55 08 8a 14 10 2a 55 14}  //weight: 1, accuracy: High
        $x_1_2 = {3c 41 72 5f 3c 47 73 04 2c 37 eb f0 3c 61 72 53 3c 67 73 04 2c 57 eb e4}  //weight: 1, accuracy: High
        $x_1_3 = {f7 da 1b d2 81 e2 b7 1d c1 04 03 c0 33 c2 49 75 e7 50 b1 20 89 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Regonid_B_2147648357_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Regonid.B"
        threat_id = "2147648357"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Regonid"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "URLOpenBlockingStreamA" ascii //weight: 1
        $x_1_2 = {00 5c 25 73 25 75 2e 25 73 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 69 6e 66 00 64 61 74 00 25 75 00 00 2a 2e 25 73 00}  //weight: 1, accuracy: High
        $x_1_4 = {8b 4d 0c f7 d8 1b c0 83 e0 07 83 c0 06 0f b7 c0 99 6a 00 52 50 e8 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_5 = "microsoft corporation" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Regonid_A_2147659130_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Regonid.gen!A"
        threat_id = "2147659130"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Regonid"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {41 43 43 45 50 54 00 43 4f 4d 4d 49 54 00 46 00 46 41 49 4c 00 50 52 55 4e 45 00 53 4b 49 50 00 54 48 45 4e}  //weight: 10, accuracy: High
        $x_10_2 = {46 83 f9 2d 8b d1 74 ?? 83 f9 2b 75 ?? 0f b6 0e 46 33 c0 83 f9 30 7c ?? 83 f9 39 7f ?? 83 e9 30 eb ?? 83 c9 ff 83 f9 ff 74}  //weight: 10, accuracy: Low
        $x_10_3 = {c1 e2 04 03 d0 0f b7 41 06 c1 e2 05 03 d0 8b 45 18 8b 48 04 8b 40 08 83 e1 07 c1 e2 04 03 d1 83 e0 03 53}  //weight: 10, accuracy: High
        $x_1_4 = {00 5c 69 6e 66 5c 25 73 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 73 72 70 61 63 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 73 72 70 61 6d 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 63 6b 63 75 73 00}  //weight: 1, accuracy: High
        $x_1_8 = {00 63 6b 63 74 6d 00}  //weight: 1, accuracy: High
        $x_1_9 = {00 75 72 6c 00}  //weight: 1, accuracy: High
        $x_1_10 = {00 68 64 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 5 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

