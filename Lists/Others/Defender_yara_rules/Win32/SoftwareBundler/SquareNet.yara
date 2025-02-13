rule SoftwareBundler_Win32_SquareNet_204428_0
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/SquareNet"
        threat_id = "204428"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "SquareNet"
        severity = "14"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 52 65 6c 65 61 73 65 5c 55 70 64 61 74 65 72 53 65 72 76 69 63 65 2e 70 64 62 00}  //weight: 1, accuracy: High
        $x_3_2 = "/updater/v%d/updaterinfo.bin" wide //weight: 3
        $x_2_3 = {7b 00 39 00 43 00 44 00 38 00 36 00 35 00 43 00 41 00 2d 00 43 00 33 00 31 00 39 00 2d 00 34 00 42 00 46 00 39 00 2d 00 38 00 35 00 37 00 37 00 2d 00 45 00 41 00 36 00 45 00 43 00 37 00 46 00 33 00 36 00 41 00 45 00 37 00 7d 00 00 00}  //weight: 2, accuracy: High
        $x_1_4 = {4d 00 65 00 64 00 69 00 61 00 44 00 65 00 76 00 53 00 76 00 63 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {57 00 69 00 6e 00 44 00 65 00 76 00 53 00 76 00 63 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = "NetworkHostSrv" wide //weight: 1
        $x_2_7 = {2f 00 75 00 70 00 64 00 61 00 74 00 65 00 72 00 2f 00 76 00 25 00 64 00 2f 00 70 00 72 00 6f 00 74 00 65 00 63 00 74 00 65 00 64 00 69 00 6e 00 66 00 6f 00 2e 00 62 00 69 00 6e 00 00 00}  //weight: 2, accuracy: High
        $x_1_8 = {4d 00 65 00 64 00 69 00 61 00 44 00 65 00 76 00 69 00 63 00 65 00 53 00 76 00 63 00 00 00}  //weight: 1, accuracy: High
        $x_1_9 = {5c 52 65 6c 65 61 73 65 5c 50 72 6f 74 65 63 74 65 64 53 65 72 76 69 63 65 2e 70 64 62 00}  //weight: 1, accuracy: High
        $x_2_10 = {73 00 74 00 61 00 74 00 65 00 3d 00 6f 00 6b 00 26 00 69 00 64 00 3d 00 25 00 73 00 26 00 6d 00 61 00 63 00 3d 00 25 00 73 00 26 00 63 00 63 00 3d 00 25 00 64 00 26 00 63 00 6c 00 69 00 63 00 6b 00 3d 00 25 00 64 00 00 00}  //weight: 2, accuracy: High
        $x_2_11 = {2f 00 65 00 6e 00 74 00 72 00 79 00 2f 00 73 00 76 00 63 00 2f 00 66 00 62 00 3f 00 00 00}  //weight: 2, accuracy: High
        $x_1_12 = {5c 75 70 64 61 74 65 72 69 6e 66 6f 00}  //weight: 1, accuracy: High
        $x_1_13 = "mac=%s&os=%s&svcver=%s&ver=%d" wide //weight: 1
        $x_1_14 = {70 72 6f 74 65 63 74 65 64 53 76 63 49 6e 66 6f 00}  //weight: 1, accuracy: High
        $x_1_15 = {67 5f 41 55 70 64 61 74 65 72 53 76 63 4e 61 6d 65 00}  //weight: 1, accuracy: High
        $x_1_16 = {33 c9 39 4c 24 08 76 13 8b 44 24 04 8a 54 24 0c 03 c1 30 10 41 3b 4c 24 08 72 ed}  //weight: 1, accuracy: High
        $x_2_17 = "ref=%s&site_id=%s&mac=%s&step=dblclick" wide //weight: 2
        $x_2_18 = "/entry/feedbackinfo/service_check?" wide //weight: 2
        $x_2_19 = {5c 00 55 00 70 00 64 00 61 00 74 00 65 00 53 00 65 00 72 00 76 00 5c 00 66 00 62 00 5f 00 69 00 6e 00 66 00 6f 00 2e 00 64 00 61 00 74 00 00 00}  //weight: 2, accuracy: High
        $x_2_20 = {26 00 63 00 6c 00 69 00 63 00 6b 00 3d 00 25 00 64 00 00 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 00 00 77 00 77 00 77 00 2e 00 00 00}  //weight: 2, accuracy: High
        $x_3_21 = "\"taskUri\" : \"/up/r%d/up.bin" ascii //weight: 3
        $x_3_22 = {2d 00 35 00 33 00 37 00 33 00 42 00 34 00 30 00 00 00}  //weight: 3, accuracy: High
        $x_3_23 = {2d 00 69 00 6b 00 65 00 37 00 30 00 38 00 39 00 62 00 00 00}  //weight: 3, accuracy: High
        $x_1_24 = "systemupdates.info/p.ashx?a=" wide //weight: 1
        $x_1_25 = {26 00 73 00 69 00 74 00 65 00 5f 00 69 00 64 00 3d 00 00 00 26 00 63 00 6c 00 69 00 63 00 6b 00 5f 00 69 00 64 00 3d 00 00 00}  //weight: 1, accuracy: High
        $x_2_26 = "{8F84BEDA-4A93-4046-97D2-7AB8B1DA49D8}" wide //weight: 2
        $x_2_27 = "global.ymtracking.com/conv?transaction_id=%s" wide //weight: 2
        $x_2_28 = {26 00 6e 00 53 00 75 00 63 00 54 00 69 00 74 00 6c 00 65 00 3d 00 00 00}  //weight: 2, accuracy: High
        $x_2_29 = {68 69 64 65 69 6e 73 74 61 6c 6c 2d 74 62 00}  //weight: 2, accuracy: High
        $x_2_30 = {40 00 25 00 64 00 26 00 7a 00 3d 00 25 00 64 00 26 00 66 00 69 00 72 00 73 00 74 00 3d 00 25 00 64 00 26 00 6c 00 61 00 74 00 65 00 73 00 74 00 3d 00 25 00 64 00 00 00}  //weight: 2, accuracy: High
        $x_3_31 = "\"taskUri\" : \"/up/1/r%d/up.bin" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule SoftwareBundler_Win32_SquareNet_204428_1
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/SquareNet"
        threat_id = "204428"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "SquareNet"
        severity = "14"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 72 6f 66 69 74 61 62 6c 65 53 6f 66 74 55 72 6c 00}  //weight: 1, accuracy: High
        $x_1_2 = {70 72 6f 66 69 74 61 62 6c 65 73 6f 66 74 2d 73 65 61 72 63 68 00}  //weight: 1, accuracy: High
        $x_1_3 = {72 65 66 3d 25 73 26 73 69 74 65 5f 69 64 3d 25 73 26 6d 61 63 3d 25 73 26 26 73 74 65 70 3d 66 69 6e 69 73 68 00}  //weight: 1, accuracy: High
        $x_2_4 = {6f 66 66 65 72 5f 69 64 3d [0-8] 26 61 66 66 5f 69 64 3d [0-16] 26 74 72 61 6e 73 61 63 74 69 6f 6e 5f 69 64}  //weight: 2, accuracy: Low
        $x_1_5 = {72 00 75 00 6e 00 5f 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 65 00 72 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {72 00 65 00 66 00 3d 00 25 00 73 00 26 00 6d 00 61 00 63 00 3d 00 25 00 73 00 26 00 74 00 62 00 5f 00 73 00 74 00 61 00 74 00 65 00 3d 00 25 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {2f 00 65 00 6e 00 74 00 72 00 79 00 2f 00 65 00 78 00 65 00 2f 00 74 00 62 00 2f 00 66 00 62 00 3f 00 00 00}  //weight: 1, accuracy: High
        $x_2_8 = {6f 66 66 65 72 5f 69 64 3d [0-8] 26 61 6d 70 3b 61 66 66 5f 69 64 3d [0-16] 26 61 6d 70 3b 74 72 61 6e 73 61 63 74 69 6f 6e 5f 69 64}  //weight: 2, accuracy: Low
        $x_2_9 = {5c 00 72 00 2e 00 74 00 78 00 74 00 00 00 00 00 6f 00 66 00 66 00 65 00 72 00 5f 00 69 00 64 00 3d 00 00 00 26 00 00 00 26 00 61 00 66 00 66 00 5f 00 69 00 64 00 3d 00 00 00 00 00 26 00 74 00 72 00 61 00 6e 00 73 00 61 00 63 00 74 00 69 00 6f 00 6e 00 5f 00 69 00 64 00 3d 00 00 00}  //weight: 2, accuracy: High
        $x_2_10 = {5c 00 72 00 2e 00 74 00 78 00 74 00 00 00 00 00 6f 00 66 00 66 00 65 00 72 00 5f 00 69 00 64 00 3d 00 00 00 26 00 00 00 72 00 65 00 66 00 3d 00 00 00 00 00 63 00 75 00 73 00 74 00 6f 00 6d 00 00 00}  //weight: 2, accuracy: High
        $x_2_11 = {2d 00 37 00 37 00 46 00 42 00 43 00 45 00 34 00 42 00 37 00 38 00 31 00 41 00 34 00 39 00 38 00 31 00 38 00 38 00 46 00 41 00 33 00 35 00 36 00 38 00 30 00 36 00 42 00 32 00 46 00 41 00 31 00 44 00 00 00}  //weight: 2, accuracy: High
        $x_2_12 = "ref=%s&site_id=%s&mac=%s&step=dblclick" wide //weight: 2
        $x_1_13 = {2f 00 69 00 6e 00 66 00 6f 00 2e 00 64 00 61 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_2_14 = {6f 00 66 00 66 00 65 00 72 00 5f 00 69 00 64 00 3d 00 00 00 26 00 00 00 72 00 65 00 66 00 3d 00 00 00 00 00 26 00 00 00 63 00 75 00 73 00 74 00 6f 00 6d 00 00 00}  //weight: 2, accuracy: High
        $x_2_15 = {2f 00 65 00 6e 00 74 00 72 00 79 00 2f 00 66 00 65 00 65 00 64 00 62 00 61 00 63 00 6b 00 69 00 6e 00 66 00 6f 00 2f 00 70 00 72 00 6f 00 64 00 75 00 63 00 74 00 69 00 6f 00 6e 00 2f 00 6c 00 6f 00 61 00 64 00 65 00 72 00 2f 00 00 00}  //weight: 2, accuracy: High
        $x_2_16 = {2f 00 65 00 6e 00 74 00 72 00 79 00 2f 00 66 00 65 00 65 00 64 00 62 00 61 00 63 00 6b 00 69 00 6e 00 66 00 6f 00 2f 00 70 00 72 00 6f 00 64 00 75 00 63 00 74 00 69 00 6f 00 6e 00 2f 00 6a 00 61 00 76 00 61 00 2f 00 00 00}  //weight: 2, accuracy: High
        $x_1_17 = {2f 00 61 00 66 00 66 00 5f 00 63 00 3f 00 6f 00 66 00 66 00 65 00 72 00 5f 00 69 00 64 00 3d 00 25 00 73 00 26 00 61 00 66 00 66 00 5f 00 69 00 64 00 3d 00 25 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_2_18 = {2f 00 65 00 6e 00 74 00 72 00 79 00 2f 00 66 00 65 00 65 00 64 00 62 00 61 00 63 00 6b 00 69 00 6e 00 66 00 6f 00 2f 00 66 00 6c 00 76 00 5f 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 65 00 72 00 2f 00 25 00 73 00 3f 00 25 00 73 00 00 00}  //weight: 2, accuracy: High
        $x_1_19 = {69 00 64 00 3d 00 25 00 73 00 26 00 6f 00 73 00 3d 00 25 00 73 00 26 00 70 00 3d 00 25 00 64 00 00 00}  //weight: 1, accuracy: High
        $x_2_20 = {6f 00 66 00 66 00 65 00 72 00 5f 00 69 00 64 00 3d 00 00 00 26 00 00 00 72 00 65 00 66 00 3d 00 00 00 00 00 26 00 00 00 63 00 75 00 73 00 00 00 74 00 6f 00 6d 00 00 00}  //weight: 2, accuracy: High
        $x_2_21 = {b9 3d 00 00 00 ba 25 00 00 00 66 89 4c 24 ?? 66 89 54 24 ?? b8 64 00 00 00 b9 26 00 00 00 ba 6f 00 00 00 66 89 44 24 ?? b8 73 00 00 00}  //weight: 2, accuracy: Low
        $x_1_22 = {2f 00 72 00 65 00 64 00 69 00 72 00 65 00 63 00 74 00 2e 00 70 00 68 00 70 00 3f 00 6f 00 66 00 66 00 65 00 72 00 5f 00 69 00 64 00 3d 00 00 00}  //weight: 1, accuracy: High
        $x_2_23 = {2f 00 65 00 6e 00 74 00 72 00 79 00 2f 00 66 00 65 00 65 00 64 00 62 00 61 00 63 00 6b 00 69 00 6e 00 66 00 6f 00 2f 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 5f 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 3f 00 00 00}  //weight: 2, accuracy: High
        $x_2_24 = "/entry/feedbackinfo/production/loader/c" wide //weight: 2
        $x_1_25 = {2f 00 74 00 72 00 61 00 63 00 65 00 3f 00 6f 00 66 00 66 00 65 00 72 00 5f 00 69 00 64 00 3d 00 25 00 73 00 26 00 61 00 66 00 66 00 5f 00 69 00 64 00 3d 00 25 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_26 = "Failed to Get Info!" wide //weight: 1
        $x_2_27 = "/entry/ipquery/get_country?ip=" wide //weight: 2
        $x_1_28 = {5c 73 65 72 76 5c 64 6f 77 6e 6c 6f 61 64 2e 64 61 74 00}  //weight: 1, accuracy: High
        $x_2_29 = {2f 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 2f 00 6c 00 6f 00 61 00 64 00 65 00 72 00 2f 00 69 00 5f 00 79 00 6d 00 5f 00 61 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 2, accuracy: High
        $x_2_30 = "/entry//feedbackinfo/production/loader/custom" wide //weight: 2
        $x_1_31 = {5c 64 6f 77 6e 6c 6f 61 64 65 72 5c 64 6f 77 6e 6c 6f 61 64 5f 6d 67 72 5c 52 65 6c 65 61 73 65 5c 6c 6f 61 64 65 72 2e 70 64 62 00}  //weight: 1, accuracy: High
        $x_2_32 = {74 00 72 00 61 00 63 00 6b 00 66 00 69 00 6c 00 65 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 2e 00 63 00 6f 00 6d 00 2f 00 65 00 6e 00 74 00 72 00 79 00 2f 00 66 00 65 00 65 00 64 00 62 00 61 00 63 00 6b 00 69 00 6e 00 66 00 6f 00 2f 00 00 00}  //weight: 2, accuracy: High
        $x_2_33 = "/download/loader/i_yeahmobi_a.exe" wide //weight: 2
        $x_2_34 = "tracking.imobitracking.net/info/custom/" wide //weight: 2
        $x_2_35 = {00 00 2f 00 69 00 6e 00 66 00 6f 00 2f 00 63 00 75 00 73 00 74 00 6f 00 6d 00 2f 00 63 00 70 00 78 00 69 00}  //weight: 2, accuracy: High
        $x_3_36 = {2f 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 2f 00 6c 00 6f 00 61 00 64 00 65 00 72 00 2f 00 69 00 5f 00 73 00 63 00 70 00 78 00 5f 00 61 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 3, accuracy: High
        $x_2_37 = "`e.mn`eds.h^rbqy^`/dyd" ascii //weight: 2
        $x_2_38 = "`e.mn`eds.h^xd`ilnch^`/dyd" ascii //weight: 2
        $x_2_39 = {8b 45 08 8a 04 07 32 45 10 0f b6 c0 50 e8 ?? ?? ?? ?? 47 3b 7d 0c 72 e8}  //weight: 2, accuracy: Low
        $x_2_40 = {39 7d 0c 76 14 8b 45 ?? 8a 1c 38 32 5d 10 e8 ?? ?? ?? ?? 47 3b 7d 0c 72 ec}  //weight: 2, accuracy: Low
        $x_2_41 = "/entry/infomgr/svc/svcinfo?" wide //weight: 2
        $x_2_42 = "\\download_mgr_photoyee\\Release\\" ascii //weight: 2
        $x_2_43 = "/entry/track/event-fb?" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

