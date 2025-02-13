rule TrojanDownloader_Win32_Tibs_2147800188_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tibs"
        threat_id = "2147800188"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
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
        $x_1_35 = "%s%s%s%s" ascii //weight: 1
        $x_1_36 = "%c%c%c%c" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_2_*) and 8 of ($x_1_*))) or
            ((6 of ($x_2_*) and 6 of ($x_1_*))) or
            ((7 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_3_*) and 5 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 6 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 7 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_3_*) and 3 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_3_*) and 4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 6 of ($x_2_*))) or
            ((3 of ($x_3_*) and 1 of ($x_2_*) and 7 of ($x_1_*))) or
            ((3 of ($x_3_*) and 2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_3_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_3_*) and 5 of ($x_2_*))) or
            ((4 of ($x_3_*) and 6 of ($x_1_*))) or
            ((4 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_3_*) and 3 of ($x_2_*))) or
            ((5 of ($x_3_*) and 3 of ($x_1_*))) or
            ((5 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((5 of ($x_3_*) and 2 of ($x_2_*))) or
            ((6 of ($x_3_*))) or
            ((1 of ($x_4_*) and 3 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_4_*) and 4 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_4_*) and 5 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 6 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 7 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 6 of ($x_2_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 8 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_4_*) and 3 of ($x_3_*) and 5 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_4_*) and 4 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 4 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_4_*) and 5 of ($x_3_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_4_*) and 2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_4_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_4_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_4_*) and 5 of ($x_2_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((2 of ($x_4_*) and 2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((2 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_4_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((2 of ($x_4_*) and 3 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*) and 3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_4_*) and 4 of ($x_3_*))) or
            ((3 of ($x_4_*) and 6 of ($x_1_*))) or
            ((3 of ($x_4_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_4_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_4_*) and 3 of ($x_2_*))) or
            ((3 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((3 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((3 of ($x_4_*) and 2 of ($x_3_*))) or
            ((1 of ($x_5_*) and 3 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_5_*) and 4 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_5_*) and 5 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 6 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 7 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 7 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_5_*) and 3 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_5_*) and 4 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 4 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_5_*) and 5 of ($x_3_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 5 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 6 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_3_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 5 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 3 of ($x_2_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 2 of ($x_3_*))) or
            ((1 of ($x_5_*) and 3 of ($x_4_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_5_*) and 3 of ($x_4_*) and 1 of ($x_3_*))) or
            ((2 of ($x_5_*) and 8 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_5_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*) and 4 of ($x_2_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*) and 5 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((2 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_5_*) and 3 of ($x_3_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 4 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_2_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*))) or
            ((2 of ($x_5_*) and 2 of ($x_4_*))) or
            ((3 of ($x_5_*) and 3 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_5_*) and 2 of ($x_2_*))) or
            ((3 of ($x_5_*) and 1 of ($x_3_*))) or
            ((3 of ($x_5_*) and 1 of ($x_4_*))) or
            ((4 of ($x_5_*))) or
            ((1 of ($x_6_*) and 2 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_6_*) and 3 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_6_*) and 4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_6_*) and 5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_6_*) and 6 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_6_*) and 2 of ($x_3_*) and 6 of ($x_1_*))) or
            ((1 of ($x_6_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_6_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_6_*) and 2 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_6_*) and 3 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_6_*) and 3 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_6_*) and 3 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_6_*) and 4 of ($x_3_*))) or
            ((1 of ($x_6_*) and 1 of ($x_4_*) and 8 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_4_*) and 1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_4_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_4_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_4_*) and 4 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 5 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_4_*) and 3 of ($x_3_*))) or
            ((1 of ($x_6_*) and 2 of ($x_4_*) and 4 of ($x_1_*))) or
            ((1 of ($x_6_*) and 2 of ($x_4_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_6_*) and 2 of ($x_4_*) and 2 of ($x_2_*))) or
            ((1 of ($x_6_*) and 2 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_6_*) and 2 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_6_*) and 2 of ($x_4_*) and 2 of ($x_3_*))) or
            ((1 of ($x_6_*) and 3 of ($x_4_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 7 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 4 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 3 of ($x_3_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_6_*) and 1 of ($x_5_*) and 2 of ($x_4_*))) or
            ((1 of ($x_6_*) and 2 of ($x_5_*) and 2 of ($x_1_*))) or
            ((1 of ($x_6_*) and 2 of ($x_5_*) and 1 of ($x_2_*))) or
            ((1 of ($x_6_*) and 2 of ($x_5_*) and 1 of ($x_3_*))) or
            ((1 of ($x_6_*) and 2 of ($x_5_*) and 1 of ($x_4_*))) or
            ((1 of ($x_6_*) and 3 of ($x_5_*))) or
            ((2 of ($x_6_*) and 6 of ($x_1_*))) or
            ((2 of ($x_6_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_6_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_6_*) and 3 of ($x_2_*))) or
            ((2 of ($x_6_*) and 1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((2 of ($x_6_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_6_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((2 of ($x_6_*) and 2 of ($x_3_*))) or
            ((2 of ($x_6_*) and 1 of ($x_4_*) and 2 of ($x_1_*))) or
            ((2 of ($x_6_*) and 1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((2 of ($x_6_*) and 1 of ($x_4_*) and 1 of ($x_3_*))) or
            ((2 of ($x_6_*) and 2 of ($x_4_*))) or
            ((2 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_2_*))) or
            ((2 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_3_*))) or
            ((2 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_4_*))) or
            ((2 of ($x_6_*) and 2 of ($x_5_*))) or
            ((3 of ($x_6_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Tibs_T_2147803940_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tibs.T"
        threat_id = "2147803940"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 c7 45 e0 14 00 66 c7 45 e2 14 00 c7 45 e4 ?? ?? ?? ?? 66 c7 45 d8 1a 00 66 c7 45 da 1a 00 c7 45 dc}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 44 24 04 8b 40 04 05 b8 00 00 00 8b 08 80 39 cc 75 06 c7 00 ?? ?? ?? ?? 83 c8 ff c2 04 00}  //weight: 1, accuracy: Low
        $x_1_3 = {42 00 49 00 54 00 53 00 00 00 00 00 52 00 70 00 63 00 53 00 73 00 00 00 61 00 64 00 76 00 61 00 70 00 69 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 00 00 00 00 6f 00 6c 00 65 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Tibs_A_2147804157_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tibs.A"
        threat_id = "2147804157"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 c5 81 38 4e 54 44 4c 75 ?? 66 81 78 04 4c 2e 75}  //weight: 10, accuracy: Low
        $x_10_2 = {c6 07 68 89 47 01 c6 47 05 c3}  //weight: 10, accuracy: High
        $x_10_3 = {81 3f 6f 6d 6d 61 75 ?? 66 81 7f 04 6e 64 75 ?? 80 7f 06 7c 75}  //weight: 10, accuracy: Low
        $x_1_4 = "KeServiceDescriptorTable" ascii //weight: 1
        $x_10_5 = {68 50 4f 53 54 58 ab b0 20 aa 8b 75 ?? f3 a4 68 20 48 54 54 58 ab 68 50 2f ?? 2e 58 ab b0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            ((4 of ($x_10_*))) or
            (all of ($x*))
        )
}

