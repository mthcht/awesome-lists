rule SoftwareBundler_Win32_Chindo_205265_0
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/Chindo"
        threat_id = "205265"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "Chindo"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "CreateMutexA(i 0, i 0, t \"JWBClient\")" ascii //weight: 5
        $x_5_2 = "\\Intrenet Explorer.lnk" ascii //weight: 5
        $x_2_3 = {5c 69 2e 72 61 72 00}  //weight: 2, accuracy: High
        $x_2_4 = {24 24 5c 77 69 6e 69 6e 69 74 2e 69 6e 69 00}  //weight: 2, accuracy: High
        $x_1_5 = {2f 73 69 6c 65 6e 74 00 67 65 74}  //weight: 1, accuracy: High
        $x_1_6 = "download_quiet" ascii //weight: 1
        $x_1_7 = {4f 70 65 6e 20 [0-12] 2e 6a 70 67 00}  //weight: 1, accuracy: Low
        $x_1_8 = {4f 70 65 6e 20 ?? ?? ?? ?? ?? ?? ?? 2f ?? ?? ?? ?? 2e 63 73 73 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule SoftwareBundler_Win32_Chindo_205265_1
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/Chindo"
        threat_id = "205265"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "Chindo"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "http://dl.static.iqiyi.com/hz/IQIYIsetup_senxing@kb010.exe" ascii //weight: 4
        $x_3_2 = "SoHuVA_4.5.77.0-c207715-nti-ng-tp-s.exe" ascii //weight: 3
        $x_2_3 = "http://int.dpool.sina.com.cn/iplookup/iplookup.php" ascii //weight: 2
        $x_2_4 = "C:\\TEMP\\2.jpg" ascii //weight: 2
        $x_1_5 = "Tencent\\QQBrowser\\uninst.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule SoftwareBundler_Win32_Chindo_205265_2
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/Chindo"
        threat_id = "205265"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "Chindo"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 31 2e 67 69 66 [0-16] 2a 28 69 20 30 29 20 69 20 2e 52 30 [0-8] 41 64 76 61 70 69 33 32 3a 3a 52 65 67 4f 70 65 6e 4b 65 79 28 69 20 30 78 38 30 30 30 30 30 30 32}  //weight: 1, accuracy: Low
        $x_1_2 = {31 2e 7a 69 70 00 2f 73 69 6c 65 6e 74 00 67 65 74 00 fd 99 80 5c 31 2e 7a 69 70 00 31 3a 31 00}  //weight: 1, accuracy: High
        $x_1_3 = {2f 32 30 2e 68 74 6d 6c 00 4f 70 65 6e 20 fd 83 80 fd 85 80 2f 32 30 2e 68 74 6d 6c 00 41}  //weight: 1, accuracy: High
        $x_1_4 = {2f 34 30 2e 68 74 6d 6c 00 4f 70 65 6e 20 fd 83 80 fd 85 80 2f 34 30 2e 68 74 6d 6c 00 41}  //weight: 1, accuracy: High
        $x_1_5 = "::CreateMutexA(i 0, i 0, t \"1\") i .r1 ?e" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule SoftwareBundler_Win32_Chindo_205265_3
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/Chindo"
        threat_id = "205265"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "Chindo"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3a 3a 43 72 65 61 74 65 4d 75 74 65 78 41 28 69 20 30 2c 20 69 20 30 2c 20 74 20 22 [0-16] 22 29 20 69 20 2e 72 31 20 3f 65}  //weight: 1, accuracy: Low
        $x_1_2 = {fd 9a 80 5c 01 00 2e 69 63 6f 00 53 6f 66 74 00 41 31 00 41 32 00 41 33 00 46 31 00 55 31}  //weight: 1, accuracy: Low
        $x_1_3 = {5c 69 2e 72 61 72 00 fd 8f 80 00 64 6f 77 6e 6c 6f 61 64 5f 71 75 69 65 74 00 31 3a 31}  //weight: 1, accuracy: High
        $x_1_4 = {5c 55 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 [0-32] 5c 55 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 [0-32] 5c 75 6e 69 6e 73 74 2e 6c 6e 6b 00}  //weight: 1, accuracy: Low
        $x_1_5 = {2e 69 63 6f 00 2f 53 49 4c 45 4e 54 00 [0-4] 4f 4b 00}  //weight: 1, accuracy: Low
        $x_1_6 = {4f 70 65 6e 20 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 6a 70 67 ?? ?? ?? ?? 5c 49 6e 74 72 65 6e 65 74 20 45 78 70 6c 6f 72 65 72 2e 6c 6e 6b ?? ?? ?? ?? 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 00 31 30 00}  //weight: 1, accuracy: Low
        $x_1_7 = {5c 69 2e 72 61 72 00 fd 8f 80 00 2f 73 69 6c 65 6e 74 00 67 65 74 00 31 3a 31}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule SoftwareBundler_Win32_Chindo_205265_4
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/Chindo"
        threat_id = "205265"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "Chindo"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "(i 0, i 0, t \"JWBClient\")" ascii //weight: 1
        $x_1_2 = {2f 70 70 74 76 2e 63 73 73 00 4f 70 65 6e [0-10] 2f 70 70 74 76 2e 63 73 73}  //weight: 1, accuracy: Low
        $x_1_3 = {5c 49 6e 74 72 65 6e 65 74 20 45 78 70 6c 6f 72 65 72 2e 6c 6e 6b 00 ?? ?? ?? 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_4 = {2f 74 65 73 74 2e 74 78 74 00 ?? ?? ?? 5c 74 65 73 74 2e 62 61 74 00 4f 70 65 6e}  //weight: 1, accuracy: Low
        $x_1_5 = {5c 7a 78 79 ?? 2e 6a 70 67 00 53 6f 66 74 [0-16] 53 6f 66 74 4e 61 6d 65 00 53 6f 66 74 4c 69 6e 6b 00 53 6f 66 74 50 72 6d 00}  //weight: 1, accuracy: Low
        $x_1_6 = {5c 55 6e 6c 6f 61 64 2e 65 78 65 00 [0-32] 5c 55 6e 6c 6f 61 64 2e 6c 6e 6b 00}  //weight: 1, accuracy: Low
        $x_1_7 = "aHR0cDovL2ludC5kcG9vbC5zaW5hLmNvbS5jbi9pcGxvb2t1cC9pcGxvb2t1cC5waHA" ascii //weight: 1
        $x_1_8 = "aHR0cDovL3NvZnRwaG90b" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule SoftwareBundler_Win32_Chindo_205265_5
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/Chindo"
        threat_id = "205265"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "Chindo"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "http://down2.uc.cn/pcbrowser/down.php?pid=4396" ascii //weight: 2
        $x_2_2 = "http://misc.wcd.qq.com/app?packageName=pcqqbrowser&channelId=81529" ascii //weight: 2
        $x_2_3 = {66 74 70 3a 2f 2f 64 6f 77 6e 6c 6f 61 64 2e 66 65 69 73 75 38 2e 63 6f 6d 3a 32 32 2f [0-48] 5f 31 32 30 32 30 30 30 ?? (30|2d|39) (30|2d|39) 2e 74 78 74}  //weight: 2, accuracy: Low
        $x_1_4 = "http://down.kuwo.cn/mbox/kuwo_jm634.exe" ascii //weight: 1
        $x_2_5 = {66 74 70 3a 2f 2f 66 2e 69 31 32 33 36 2e 63 6f 6d 2f 72 61 76 [0-60] 2f 72 61 76 33 34 39 30 30 32 32 2e 65 78 65}  //weight: 2, accuracy: Low
        $x_1_6 = {68 74 74 70 3a 2f 2f 77 2e 78 2e 62 61 69 64 75 2e 63 6f 6d 2f 67 6f 2f (6d 69|66 75) 2f 32 30 31 2f 31 32 30 32 30 30 30 ?? (30|2d|39) (30|2d|39)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

