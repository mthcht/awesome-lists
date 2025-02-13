rule TrojanDownloader_Win32_Seimon_A_2147598869_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Seimon.gen!A"
        threat_id = "2147598869"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Seimon"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "%s%s%s_%s" ascii //weight: 1
        $x_1_2 = "%MACADDR" ascii //weight: 1
        $x_2_3 = "_xml.php?aff_id=%AFFID&lunch_id=%LUNCHID" ascii //weight: 2
        $x_1_4 = ".tagrevenue.net/" ascii //weight: 1
        $x_2_5 = {5f 71 75 69 74 65 76 65 6e 74 00 [0-4] 68 74 74 70 3a 2f 2f 77 77 77 2e 6d 69 63 72 6f 73 6f 66 74 2e}  //weight: 2, accuracy: Low
        $x_1_6 = {50 61 63 6b 65 74 53 6e 69 66 66 65 72 43 6c 61 73 73 31 00}  //weight: 1, accuracy: High
        $x_1_7 = {77 65 6c 2d 66 6f 72 6d 65 64 2e 00}  //weight: 1, accuracy: High
        $x_1_8 = "proc.php?mode=1&key=%" ascii //weight: 1
        $x_2_9 = {25 73 5c 65 6c 2e 64 61 74 00 00 00 25 57 49 4e 44 4f 57 53}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Seimon_D_2147610550_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Seimon.D"
        threat_id = "2147610550"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Seimon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6c 6f 67 2f 70 72 6f 63 2e 70 68 70 3f [0-10] 6b 65 79 3d 25 [0-8] 49 44}  //weight: 2, accuracy: Low
        $x_2_2 = {68 74 74 70 3a 2f 2f 77 77 77 2e [0-10] 2e 63 6f 6d 2f 62 69 6e 2f [0-10] 2e 70 68 70}  //weight: 2, accuracy: Low
        $x_1_3 = "mutex_" ascii //weight: 1
        $x_1_4 = "%MACADDR" ascii //weight: 1
        $x_1_5 = "%s\\msagent\\%s" ascii //weight: 1
        $x_1_6 = "%s_mtx_name" ascii //weight: 1
        $x_1_7 = {5b 49 6e 74 65 72 6e 65 74 53 68 6f 72 74 63 75 74 5d 0d 0a 55 52 4c 3d 25 73 0d 0a 49 63 6f 6e 49 6e 64 65 78 3d 30 0d 0a 49 63 6f 6e 46 69 6c 65 3d 25 73}  //weight: 1, accuracy: High
        $x_1_8 = "%ACTION" ascii //weight: 1
        $x_1_9 = "%COMPANY" ascii //weight: 1
        $x_1_10 = "%s\\%d.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 7 of ($x_1_*))) or
            ((2 of ($x_2_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

