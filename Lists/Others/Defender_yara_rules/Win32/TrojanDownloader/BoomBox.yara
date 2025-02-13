rule TrojanDownloader_Win32_BoomBox_A_2147781392_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/BoomBox.A!dha"
        threat_id = "2147781392"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "BoomBox"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {67 65 74 5f 61 64 5f 69 6e 66 6f 00 67 65 74 5f 68 6f ?? 74 5f 69 6e 66 6f 00 50 61 74 68 4c 6f 77 65 72 42 61 63 6b 75 70 00}  //weight: 1, accuracy: Low
        $x_1_2 = {15 4c 00 44 00 41 00 50 00 3a 00 2f 00 2f 00 7b 00 ?? 00 7d 00 00 59 28 00 26 00 28 00 6f 00 62 00 6a 00 65 00 63 00 74 00 43 00 6c 00 61 00 ?? 00 73 00 3d 00 75 00 73 00 65 00 72 00 29 00}  //weight: 1, accuracy: Low
        $x_1_3 = {0a 00 64 00 69 00 73 00 74 00 69 00 ?? 00 67 00 75 00 69 00 73 00 68 00 65 00 64 00 4e 00 61 00 6d 00 65 00 3a 00 7b 00 33 00 7d 00 0a 00 73 00 61 00 ?? 00 61 00 63 00 63 00 6f 00 75 00 6e 00 74 00 6e 00 61 00 6d 00 65 00 3a 00 7b 00 30 00 7d 00 0a 00}  //weight: 1, accuracy: Low
        $x_1_4 = {61 65 73 5f 63 72 79 70 74 5f 72 65 61 64 00 67 65 74 5f 50 72 6f ?? 65 72 74 69 65 73 54 6f 4c 6f 61 64 00 41 64 64 00}  //weight: 1, accuracy: Low
        $x_1_5 = {61 65 73 5f 63 72 79 70 74 5f 77 72 69 74 65 00 43 6f 6d 70 69 6c 65 72 ?? 65 6e 65 72 61 74 65 64 41 74 74 72 69 62 75 74 65 00 47 75 69 64 41 74 74 72 69 62 75 74 65 00}  //weight: 1, accuracy: Low
        $x_1_6 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 00 55 70 6c 6f 61 64 ?? 69 6c 65 00 61 64 64 5f 72 75 6c 65 00}  //weight: 1, accuracy: Low
        $x_1_7 = {67 65 74 5f 4e 61 6d 65 00 67 65 74 5f 44 6f 6d 61 ?? 6e 4e 61 6d 65 00 67 65 74 5f 48 6f 73 74 4e 61 6d 65 00 47 65 74 48 6f 73 74 4e 61 6d 65}  //weight: 1, accuracy: Low
        $x_1_8 = {23 2f 00 32 00 2f 00 66 00 69 00 ?? 00 65 00 73 00 2f 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 ?? 00 00 09 50 00 4f 00 53 00 54 00 00 07 2a 00 2f 00 2a 00 00}  //weight: 1, accuracy: Low
        $x_1_9 = {2f 00 32 00 2f 00 66 00 69 00 6c 00 ?? 00 73 00 2f 00 75 00 70 00 6c 00 6f 00 61 00 64 00 00 31 61 00 70 00 70 00 6c 00 69 00 ?? 00 61 00 74 00 69 00 6f 00 6e 00 2f 00 6f 00 63 00 74 00 65 00 74 00 2d 00 73 00 74 00 72 00 65 00 61 00 6d 00 01 80 a3 22 00 2c 00 22 00 6d 00 6f 00 64 00 65 00 22 00}  //weight: 1, accuracy: Low
        $x_1_10 = {48 00 4e 00 3a 00 7b 00 30 00 7d 00 00 0b ?? 00 3a 00 7b 00 30 00 7d 00 00 07 49 00 50 00 3a 00 00 03 7c 00 00 1f 7b 00 30 00 7d 00 2c 00 ?? 00 31 00 7d 00 2c 00 7b 00 32 00 7d 00 2c 00 7b 00 33 00 7d 00 00}  //weight: 1, accuracy: Low
        $x_1_11 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 ?? 00 5c 00 4e 00 61 00 74 00 69 00 76 00 65 00 43 00 61 00 63 00 68 00 65 00 00 27 5c 00 53 00 79 00 ?? 00 74 00 65 00 6d 00 43 00 65 00 72 00 74 00 69 00 66 00 69 00 63 00 61 00 74 00 65 00 73 00 00 09 5c 00 4c 00 69 00 62 00 00}  //weight: 1, accuracy: Low
        $x_1_12 = {2f 00 74 00 6d 00 70 00 2f 00 6d 00 61 00 6e 00 ?? 00 61 00 6c 00 2e 00 70 00 64 00 66 00 00 27 5c 00 4e 00 61 00 74 00 69 00 76 00 65 00 43 00 61 00 63 00 ?? 00 65 00 53 00 76 00 63 00 2e 00 64 00 6c 00 6c 00 00}  //weight: 1, accuracy: Low
        $x_1_13 = {27 4d 00 69 00 63 00 72 00 6f 00 4e 00 61 00 74 00 ?? 00 76 00 65 00 43 00 61 00 63 00 68 00 65 00 53 00 76 00 63 00 00 29 72 00 75 00 6e 00 ?? 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 20 00 7b 00 30 00 7d 00 20 00 7b 00 31 00 7d 00 00}  //weight: 1, accuracy: Low
        $x_1_14 = {25 5f 00 63 00 6f 00 6e 00 66 00 69 00 67 00 4e 00 ?? 00 74 00 69 00 76 00 65 00 43 00 61 00 63 00 68 00 65 00 00 1f 2f 00 74 00 6d 00 70 00 2f 00 72 00 65 00 ?? 00 64 00 6d 00 65 00 2e 00 70 00 64 00 66 00 00}  //weight: 1, accuracy: Low
        $x_1_15 = {2b 5c 00 5c 00 43 00 65 00 72 00 74 00 50 00 4b 00 49 00 ?? 00 72 00 6f 00 76 00 69 00 64 00 65 00 72 00 2e 00 64 00 6c 00 6c 00 00 19 72 00 75 00 6e 00 64 00 ?? 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 00}  //weight: 1, accuracy: Low
        $x_1_16 = {4d 5c 00 4e 00 61 00 74 00 69 00 76 00 65 00 43 00 61 00 ?? 00 68 00 65 00 53 00 76 00 63 00 2e 00 64 00 6c 00 6c 00 20 00 5f 00 63 00 6f 00 6e 00 66 00 69 00 ?? 00 4e 00 61 00 74 00 69 00 76 00 65 00 43 00 61 00 63 00 68 00 65 00 00}  //weight: 1, accuracy: Low
        $x_1_17 = {19 65 00 78 00 70 00 6c 00 ?? 00 72 00 65 00 72 00 2e 00 65 00 78 00 65 00 00 53 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 ?? 00 5c 00 4e 00 61 00 74 00 69 00 76 00 65 00 43 00 61 00 63 00 68 00 65 00 5c 00 4e 00 61 00 74 00 69 00 76 00 65 00 43 00 61 00 63 00 68 00 65 00 53 00 76 00 63 00 2e 00 64 00 6c 00 6c 00 00}  //weight: 1, accuracy: Low
        $x_1_18 = {11 2f 00 6f 00 6c 00 64 00 2f 00 7b ?? 30 00 7d 00 00 11 2f 00 6e 00 65 00 77 00 2f 00 7b 00 30 00 7d 00 00}  //weight: 1, accuracy: Low
        $x_1_19 = {21 31 00 32 00 33 00 33 00 74 00 30 00 34 00 ?? 00 37 00 6a 00 6e 00 33 00 6e 00 34 00 72 00 67 00 00}  //weight: 1, accuracy: Low
        $x_1_20 = {41 31 00 32 00 33 00 64 00 6f 00 33 00 79 00 ?? 00 72 00 33 00 37 00 38 00 6f 00 35 00 74 00 33 00 34 00 6f 00 6e 00 66 00 37 00 74 00 33 00 ?? 00 35 00 37 00 33 00 74 00 66 00 6f 00 37 00 33 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_BoomBox_A_2147782075_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/BoomBox.A!MTB"
        threat_id = "2147782075"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "BoomBox"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "BOOM" ascii //weight: 3
        $x_3_2 = "is_downloadable" ascii //weight: 3
        $x_3_3 = "Bearer" ascii //weight: 3
        $x_3_4 = "GetIPGlobalProperties" ascii //weight: 3
        $x_3_5 = "1233t04p7jn3n4rg" ascii //weight: 3
        $x_3_6 = "123do3y4r378o5t34onf7t3o573tfo73" ascii //weight: 3
        $x_3_7 = "aes_crypt" ascii //weight: 3
        $x_3_8 = "/tmp/readme.pdf" ascii //weight: 3
        $x_3_9 = "\\NativeCacheSvc.dll _configNativeCache" ascii //weight: 3
        $x_3_10 = "DownloadFile" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

