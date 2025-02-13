rule TrojanDownloader_Win32_Vxgame_2147803761_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Vxgame"
        threat_id = "2147803761"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Vxgame"
        severity = "37"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {8b fe 83 c9 ff 33 c0 33 d2 f2 ae f7 d1 49 74 15 80 04 32}  //weight: 6, accuracy: High
        $x_6_2 = {53 ff 15 70 31 30 40 00 0f 42 37 c0 33 db 33 44 04 14 00 00 89 85}  //weight: 6, accuracy: High
        $x_6_3 = {ff 15 6c 10 40 00 0f b7 c0 3d 04 14 00 00 89 85}  //weight: 6, accuracy: High
        $x_5_4 = "usbgg5bmm" ascii //weight: 5
        $x_5_5 = "0bempbe/qiq" ascii //weight: 5
        $x_5_6 = "iuuq;00" ascii //weight: 5
        $x_5_7 = {83 c8 ff 40 80 3c 01 00 75 f9}  //weight: 5, accuracy: High
        $x_5_8 = {83 c4 38 89 c3 89 f0 25 ff 00 00 00 83 c0 1d}  //weight: 5, accuracy: High
        $x_5_9 = "netsh firewall set allowedprogram '%s' enable" ascii //weight: 5
        $x_4_10 = {2f 63 6a 7b 00 75 79}  //weight: 4, accuracy: High
        $x_4_11 = {ff ff 10 04 00 00 0f 84}  //weight: 4, accuracy: High
        $x_4_12 = {ff ff 10 04 00 00 bf b0}  //weight: 4, accuracy: High
        $x_3_13 = "traff4all.biz" ascii //weight: 3
        $x_3_14 = {00 00 63 3a 00 00 53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65}  //weight: 3, accuracy: High
        $x_3_15 = "DisableTaskMgr" ascii //weight: 3
        $x_3_16 = "/qiq" ascii //weight: 3
        $x_3_17 = "/cj{" ascii //weight: 3
        $x_3_18 = "vxv.php" ascii //weight: 3
        $x_3_19 = "cntr.php" ascii //weight: 3
        $x_3_20 = "svcp.csv" ascii //weight: 3
        $x_3_21 = {65 00 25 73 5c 76 78}  //weight: 3, accuracy: High
        $x_2_22 = "tibs." ascii //weight: 2
        $x_2_23 = "proxy." ascii //weight: 2
        $x_2_24 = "zgame1.exe" ascii //weight: 2
        $x_2_25 = "kernels8.exe" ascii //weight: 2
        $x_2_26 = {89 d8 25 ff 00 00 00 83 c0 17 88 85}  //weight: 2, accuracy: High
        $x_2_27 = {ff ff 89 da c1 ea 08 88 95}  //weight: 2, accuracy: High
        $x_2_28 = "notoutpost" ascii //weight: 2
        $x_1_29 = "hide_" ascii //weight: 1
        $x_1_30 = "un_hide_" ascii //weight: 1
        $x_1_31 = "_hide" ascii //weight: 1
        $x_1_32 = "_un_hide" ascii //weight: 1
        $x_1_33 = "_unhide" ascii //weight: 1
        $x_1_34 = "GetSystemDefaultLangID" ascii //weight: 1
        $x_1_35 = "ObtainUserAgentString" ascii //weight: 1
        $x_1_36 = "InternetReadFile" ascii //weight: 1
        $x_1_37 = "GetSystemDirectory" ascii //weight: 1
        $x_1_38 = "NtQuerySystemInformation" ascii //weight: 1
        $x_1_39 = "NtQueryDirectoryFile" ascii //weight: 1
        $x_1_40 = "NtEnumerateValueKey" ascii //weight: 1
        $x_1_41 = "%s%s%s%s" ascii //weight: 1
        $x_1_42 = "%c%c%c%c" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 14 of ($x_1_*))) or
            ((4 of ($x_2_*) and 12 of ($x_1_*))) or
            ((5 of ($x_2_*) and 10 of ($x_1_*))) or
            ((6 of ($x_2_*) and 8 of ($x_1_*))) or
            ((7 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 13 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 11 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_3_*) and 5 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_3_*) and 6 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 7 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_3_*) and 14 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 12 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*) and 10 of ($x_1_*))) or
            ((2 of ($x_3_*) and 3 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_3_*) and 4 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_3_*) and 5 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 6 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 7 of ($x_2_*))) or
            ((3 of ($x_3_*) and 11 of ($x_1_*))) or
            ((3 of ($x_3_*) and 1 of ($x_2_*) and 9 of ($x_1_*))) or
            ((3 of ($x_3_*) and 2 of ($x_2_*) and 7 of ($x_1_*))) or
            ((3 of ($x_3_*) and 3 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_3_*) and 4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_3_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_3_*) and 6 of ($x_2_*))) or
            ((4 of ($x_3_*) and 8 of ($x_1_*))) or
            ((4 of ($x_3_*) and 1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((4 of ($x_3_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_3_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_3_*) and 4 of ($x_2_*))) or
            ((5 of ($x_3_*) and 5 of ($x_1_*))) or
            ((5 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((5 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((5 of ($x_3_*) and 3 of ($x_2_*))) or
            ((6 of ($x_3_*) and 2 of ($x_1_*))) or
            ((6 of ($x_3_*) and 1 of ($x_2_*))) or
            ((7 of ($x_3_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 14 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 12 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_4_*) and 4 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_4_*) and 5 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_4_*) and 6 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 7 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 13 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 11 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 6 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 7 of ($x_2_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 10 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_4_*) and 3 of ($x_3_*) and 7 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_4_*) and 4 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 4 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 4 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_4_*) and 5 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 5 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_4_*) and 6 of ($x_3_*))) or
            ((2 of ($x_4_*) and 12 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*) and 10 of ($x_1_*))) or
            ((2 of ($x_4_*) and 2 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_4_*) and 3 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_4_*) and 4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_4_*) and 5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_4_*) and 6 of ($x_2_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*) and 9 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 7 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*) and 5 of ($x_2_*))) or
            ((2 of ($x_4_*) and 2 of ($x_3_*) and 6 of ($x_1_*))) or
            ((2 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_4_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_4_*) and 2 of ($x_3_*) and 3 of ($x_2_*))) or
            ((2 of ($x_4_*) and 3 of ($x_3_*) and 3 of ($x_1_*))) or
            ((2 of ($x_4_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*) and 3 of ($x_3_*) and 2 of ($x_2_*))) or
            ((2 of ($x_4_*) and 4 of ($x_3_*))) or
            ((3 of ($x_4_*) and 8 of ($x_1_*))) or
            ((3 of ($x_4_*) and 1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_4_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_4_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_4_*) and 4 of ($x_2_*))) or
            ((3 of ($x_4_*) and 1 of ($x_3_*) and 5 of ($x_1_*))) or
            ((3 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((3 of ($x_4_*) and 2 of ($x_3_*) and 2 of ($x_1_*))) or
            ((3 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((3 of ($x_4_*) and 3 of ($x_3_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 13 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_2_*) and 11 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_5_*) and 4 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_5_*) and 5 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_5_*) and 6 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 7 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 12 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 6 of ($x_2_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 9 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_5_*) and 3 of ($x_3_*) and 6 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_5_*) and 4 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 4 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 4 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_5_*) and 5 of ($x_3_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 11 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 6 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 8 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 5 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 4 of ($x_3_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 7 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 4 of ($x_2_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 3 of ($x_3_*))) or
            ((1 of ($x_5_*) and 3 of ($x_4_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_4_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_4_*) and 2 of ($x_2_*))) or
            ((1 of ($x_5_*) and 3 of ($x_4_*) and 1 of ($x_3_*))) or
            ((2 of ($x_5_*) and 10 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_5_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_5_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*) and 5 of ($x_2_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((2 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((2 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_5_*) and 4 of ($x_3_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 6 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_2_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*))) or
            ((2 of ($x_5_*) and 2 of ($x_4_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_2_*))) or
            ((2 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_3_*))) or
            ((2 of ($x_5_*) and 3 of ($x_4_*))) or
            ((3 of ($x_5_*) and 5 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_5_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_5_*) and 3 of ($x_2_*))) or
            ((3 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((3 of ($x_5_*) and 2 of ($x_3_*))) or
            ((3 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((3 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*))) or
            ((3 of ($x_5_*) and 2 of ($x_4_*))) or
            ((4 of ($x_5_*))) or
            ((1 of ($x_6_*) and 14 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_2_*) and 12 of ($x_1_*))) or
            ((1 of ($x_6_*) and 2 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_6_*) and 3 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_6_*) and 4 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_6_*) and 5 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_6_*) and 6 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_6_*) and 7 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_3_*) and 11 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_3_*) and 6 of ($x_2_*))) or
            ((1 of ($x_6_*) and 2 of ($x_3_*) and 8 of ($x_1_*))) or
            ((1 of ($x_6_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_6_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_6_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_6_*) and 2 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_6_*) and 3 of ($x_3_*) and 5 of ($x_1_*))) or
            ((1 of ($x_6_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_6_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_6_*) and 3 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_6_*) and 4 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_6_*) and 4 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_6_*) and 5 of ($x_3_*))) or
            ((1 of ($x_6_*) and 1 of ($x_4_*) and 10 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_4_*) and 1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_4_*) and 2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_4_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_4_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_4_*) and 5 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_4_*) and 3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_4_*) and 4 of ($x_3_*))) or
            ((1 of ($x_6_*) and 2 of ($x_4_*) and 6 of ($x_1_*))) or
            ((1 of ($x_6_*) and 2 of ($x_4_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_6_*) and 2 of ($x_4_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_6_*) and 2 of ($x_4_*) and 3 of ($x_2_*))) or
            ((1 of ($x_6_*) and 2 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_6_*) and 2 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_6_*) and 2 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_6_*) and 2 of ($x_4_*) and 2 of ($x_3_*))) or
            ((1 of ($x_6_*) and 3 of ($x_4_*) and 2 of ($x_1_*))) or
            ((1 of ($x_6_*) and 3 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_6_*) and 3 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 9 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 5 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 6 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 3 of ($x_3_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 5 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 3 of ($x_4_*))) or
            ((1 of ($x_6_*) and 2 of ($x_5_*) and 4 of ($x_1_*))) or
            ((1 of ($x_6_*) and 2 of ($x_5_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_6_*) and 2 of ($x_5_*) and 2 of ($x_2_*))) or
            ((1 of ($x_6_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_6_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_6_*) and 2 of ($x_5_*) and 2 of ($x_3_*))) or
            ((1 of ($x_6_*) and 2 of ($x_5_*) and 1 of ($x_4_*))) or
            ((1 of ($x_6_*) and 3 of ($x_5_*))) or
            ((2 of ($x_6_*) and 8 of ($x_1_*))) or
            ((2 of ($x_6_*) and 1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_6_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_6_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_6_*) and 4 of ($x_2_*))) or
            ((2 of ($x_6_*) and 1 of ($x_3_*) and 5 of ($x_1_*))) or
            ((2 of ($x_6_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_6_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_6_*) and 1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((2 of ($x_6_*) and 2 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_6_*) and 2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_6_*) and 3 of ($x_3_*))) or
            ((2 of ($x_6_*) and 1 of ($x_4_*) and 4 of ($x_1_*))) or
            ((2 of ($x_6_*) and 1 of ($x_4_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_6_*) and 1 of ($x_4_*) and 2 of ($x_2_*))) or
            ((2 of ($x_6_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_6_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_6_*) and 1 of ($x_4_*) and 2 of ($x_3_*))) or
            ((2 of ($x_6_*) and 2 of ($x_4_*))) or
            ((2 of ($x_6_*) and 1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((2 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_6_*) and 1 of ($x_5_*) and 2 of ($x_2_*))) or
            ((2 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_3_*))) or
            ((2 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_4_*))) or
            ((2 of ($x_6_*) and 2 of ($x_5_*))) or
            ((3 of ($x_6_*) and 2 of ($x_1_*))) or
            ((3 of ($x_6_*) and 1 of ($x_2_*))) or
            ((3 of ($x_6_*) and 1 of ($x_3_*))) or
            ((3 of ($x_6_*) and 1 of ($x_4_*))) or
            ((3 of ($x_6_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

