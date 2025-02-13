rule TrojanDownloader_Win32_FakeIE_A_2147687999_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/FakeIE.A"
        threat_id = "2147687999"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeIE"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".php?tn=00005079_pg" wide //weight: 1
        $x_1_2 = "FEATURE_BROWSER_EMULATION" wide //weight: 1
        $x_1_3 = "Internet Explorer" wide //weight: 1
        $x_1_4 = {43 00 3a 00 5c 00 [0-64] 2e 00 64 00 6c 00 6c 00}  //weight: 1, accuracy: Low
        $x_1_5 = {00 43 35 38 4d 65 6e 75 42 61 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_FakeIE_A_2147687999_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/FakeIE.A"
        threat_id = "2147687999"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeIE"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".php?tn=00005079_pg" wide //weight: 1
        $x_1_2 = "tn=00005079_2_pg&" wide //weight: 1
        $x_1_3 = "&tn=00005079_pg_1" wide //weight: 1
        $x_1_4 = "hc\\hcard\\runmeconfig\\" wide //weight: 1
        $x_1_5 = "FEATURE_BROWSER_EMULATION" wide //weight: 1
        $x_1_6 = "Internet Explorer" wide //weight: 1
        $x_1_7 = {52 00 65 00 64 00 69 00 72 00 65 00 63 00 74 00 55 00 72 00 6c 00 [0-5] 57 00 65 00 62 00 42 00 72 00 6f 00 77 00 65 00 72 00 43 00 66 00 67 00}  //weight: 1, accuracy: Low
        $x_1_8 = {58 00 75 00 6e 00 6c 00 65 00 69 00 [0-16] 43 00 6f 00 6e 00 66 00 69 00 67 00}  //weight: 1, accuracy: Low
        $x_1_9 = {58 00 75 00 6e 00 6c 00 65 00 69 00 [0-32] 55 00 73 00 65 00 72 00 [0-32] 4f 00 6e 00 6c 00 79 00 49 00 45 00}  //weight: 1, accuracy: Low
        $x_1_10 = {43 00 6f 00 6e 00 66 00 69 00 67 00 [0-32] 43 00 6f 00 6e 00 66 00 69 00 67 00 [0-32] 43 00 6f 00 6e 00 66 00 69 00 67 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule TrojanDownloader_Win32_FakeIE_B_2147696788_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/FakeIE.B"
        threat_id = "2147696788"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeIE"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 6d 61 67 6e 65 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 48 74 6d 6c 56 69 65 77 65 72 00}  //weight: 1, accuracy: High
        $x_1_3 = "http://www.2345.com" ascii //weight: 1
        $x_1_4 = "http://vod.7ibt.com/index.php?url=" ascii //weight: 1
        $x_1_5 = "F7FC1AE45C5C4758AF03EF19F18A395D" ascii //weight: 1
        $x_1_6 = "27bb20fdd3e145e4bee3db39ddd6e64c" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

