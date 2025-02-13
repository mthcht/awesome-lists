rule TrojanDownloader_Win32_Virtumonde_2147800913_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Virtumonde"
        threat_id = "2147800913"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Virtumonde"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {61 64 64 69 6e 73 2f 2a 2e 2a 00 00 00}  //weight: 2, accuracy: High
        $x_2_2 = {41 70 70 50 61 74 63 68 2f 2a 2e 2a 00 00 00}  //weight: 2, accuracy: High
        $x_2_3 = {43 75 72 73 6f 72 73 2f 2a 2e 2a 00 00 00}  //weight: 2, accuracy: High
        $x_2_4 = {52 65 67 69 73 74 72 61 74 69 6f 6e 2f 2a 2e 2a 00 00 00}  //weight: 2, accuracy: High
        $x_2_5 = {57 69 6e 64 6f 77 73 20 55 70 64 61 74 65 20 53 65 74 75 70 20 46 69 6c 65 73 2f 2a 2e 2a 00 00 00}  //weight: 2, accuracy: High
        $x_2_6 = {00 00 00 6d 69 6c 00 67 6f 76 00}  //weight: 2, accuracy: High
        $x_2_7 = {63 3a 5c 69 6e 73 74 31 2e 68 74 6d 00 00 00 00 63 3a 5c 78 2e 63 61 62 00 00 00}  //weight: 2, accuracy: High
        $x_2_8 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 4f 6e 63 65 00 00}  //weight: 2, accuracy: High
        $x_1_9 = {6f 70 65 6e 00 00 00 00 25 75 00 00 6d 79 5f 74 69 6d 65 3a 00}  //weight: 1, accuracy: High
        $x_1_10 = "*WinLogon" ascii //weight: 1
        $x_1_11 = "SysUpdIsRunningMutex" ascii //weight: 1
        $x_1_12 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 53 79 73 55 70 64 00 00 00 5f 75 70 64 61 74 65 2e 64 61 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_2_*) and 3 of ($x_1_*))) or
            ((8 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Virtumonde_2147800913_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Virtumonde"
        threat_id = "2147800913"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Virtumonde"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "45"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {61 64 64 69 6e 73 ?? 2a 2e 2a 00 00 00}  //weight: 10, accuracy: Low
        $x_10_2 = {41 70 70 50 61 74 63 68 ?? 2a 2e 2a 00 00 00}  //weight: 10, accuracy: Low
        $x_10_3 = {43 75 72 73 6f 72 73 ?? 2a 2e 2a 00 00 00}  //weight: 10, accuracy: Low
        $x_10_4 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 00 00 00}  //weight: 10, accuracy: High
        $x_5_5 = "SOFTWARE\\Microsoft\\SysUpd" ascii //weight: 5
        $x_5_6 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e 5c 4e 6f 74 69 66 79 5c 00 00 00}  //weight: 5, accuracy: High
        $x_1_7 = "bin;bas;bak;cab;cat;cmd;com;cr;c;drv;db;disk;dll;dns" ascii //weight: 1
        $x_1_8 = "bar;va;nati;ca;cac;da;pa;sa;ibn;abs;abk;acb;act;mcd;ocm;rc;c;rdv" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

