rule TrojanSpy_Win32_Travnet_A_2147671600_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Travnet.A"
        threat_id = "2147671600"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Travnet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4e 65 74 54 72 61 76 [0-1] 6c 65 72 20 49 73 20 52 75 6e 6e 69 6e 67 21 00}  //weight: 1, accuracy: Low
        $x_1_2 = {74 72 61 76 6c 65 72 62 61 63 6b 69 6e 66 6f 2d 25 64 2d 25 64 2d 25 64 2d 25 64 2d 25 64 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_3 = {25 73 5c 73 79 73 74 65 6d 5f 74 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_4 = {25 73 5c 73 79 73 74 65 6d 5c 63 6f 6e 66 69 67 5f 74 2e 64 61 74 00}  //weight: 1, accuracy: High
        $x_1_5 = {2e 2e 2f 75 70 64 61 74 61 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_6 = "action=updated&hostid=" ascii //weight: 1
        $x_1_7 = "&hostip=%s&filename=%s&filestart=%u&filetext=" ascii //weight: 1
        $x_1_8 = {44 4c 4c 2e 64 6c 6c 00 53 65 72 76 69 63 65 4d 61 69 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule TrojanSpy_Win32_Travnet_B_2147671601_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Travnet.B"
        threat_id = "2147671601"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Travnet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 ec 60 ea 00 00 57 51 6a 02 50 ff d6 8d 45 ec 57 50 6a 05 ff 75 08 ff d6 8d 45 ec 57 50 6a 06 ff 75 08 ff d6}  //weight: 1, accuracy: High
        $x_1_2 = {8b 4c 24 04 57 f7 c1 03 00 00 00 74 ?? 8a 01 41 84 c0 74 ?? f7 c1 03 00 00 00 75 ?? 8b 01 ba ff fe fe 7e 03 d0 83 f0 ff 33 c2 83 c1 04 a9 00 01 01 81}  //weight: 1, accuracy: Low
        $x_1_3 = "%snetmgr." ascii //weight: 1
        $x_1_4 = {4e 61 6d 65 3d 25 73 0a 50 61 67 65 3d 25 75}  //weight: 1, accuracy: High
        $x_1_5 = "%s?action=gotcmd&hostid" ascii //weight: 1
        $x_1_6 = "enumfs.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_Win32_Travnet_C_2147682120_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Travnet.C"
        threat_id = "2147682120"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Travnet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "141"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {74 72 61 76 6c 65 72 62 61 63 6b 69 6e 66 6f 2d 25 64 2d 25 64 2d 25 64 2d 25 64 2d 25 64 2e 64 6c 6c 00}  //weight: 100, accuracy: High
        $x_20_2 = {25 73 5c 73 79 73 74 65 6d 5f 74 2e 64 6c 6c 00}  //weight: 20, accuracy: High
        $x_20_3 = {25 73 5c 73 79 73 74 65 6d 5c 63 6f 6e 66 69 67 5f 74 2e 64 61 74 00}  //weight: 20, accuracy: High
        $x_5_4 = "%s?action=getcmd&hostid=%s&hostname=%s" ascii //weight: 5
        $x_5_5 = {64 31 3d 25 73 0a 64 69 72 63 6f 75 6e 74 3d 31}  //weight: 5, accuracy: High
        $x_1_6 = "ntvba00.tmp\\" ascii //weight: 1
        $x_1_7 = "%s\\uenumfs.ini" ascii //weight: 1
        $x_1_8 = "dnlist.ini" ascii //weight: 1
        $x_1_9 = "\\stat_t.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 2 of ($x_20_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_20_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

