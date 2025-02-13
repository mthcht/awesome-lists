rule TrojanDownloader_Win32_Gendwnurl_J_2147718552_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Gendwnurl.J!bit"
        threat_id = "2147718552"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Gendwnurl"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 22 49 45 58 20 28 28 6e 65 77 2d 6f 62 6a 65 63 74 20 6e 65 74 2e 77 65 62 63 6c 69 65 6e 74 29 2e 64 6f 77 6e 6c 6f 61 64 73 74 72 69 6e 67 28 27 68 74 74 70 [0-48] 61 74 74 61 63 6b}  //weight: 1, accuracy: Low
        $x_1_2 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 22 49 45 58 20 28 28 6e 65 77 2d 6f 62 6a 65 63 74 20 6e 65 74 2e 77 65 62 63 6c 69 65 6e 74 29 2e 64 6f 77 6e 6c 6f 61 64 73 74 72 69 6e 67 28 27 68 74 74 70 [0-48] 70 61 79 6c 6f 61 64}  //weight: 1, accuracy: Low
        $x_1_3 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 22 49 45 58 20 28 28 6e 65 77 2d 6f 62 6a 65 63 74 20 6e 65 74 2e 77 65 62 63 6c 69 65 6e 74 29 2e 64 6f 77 6e 6c 6f 61 64 73 74 72 69 6e 67 28 27 68 74 74 70 [0-48] 70 6f 77 65 72 73 68 65 6c 6c 5f 69 6e 6a 65 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_4 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 22 49 45 58 20 28 28 6e 65 77 2d 6f 62 6a 65 63 74 20 6e 65 74 2e 77 65 62 63 6c 69 65 6e 74 29 2e 64 6f 77 6e 6c 6f 61 64 73 74 72 69 6e 67 28 27 68 74 74 70 [0-48] 73 68 65 6c 6c 63 6f 64 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_Win32_Gendwnurl_Y_2147719501_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Gendwnurl.Y!bit"
        threat_id = "2147719501"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Gendwnurl"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Local\\bwapi_shared_memory_game_list" ascii //weight: 1
        $x_1_2 = {40 00 c6 45 ?? 68 c6 45 ?? 74 c6 45 ?? 74 c6 45 ?? 70}  //weight: 1, accuracy: Low
        $x_1_3 = {33 c0 89 45 ?? 89 45 08 00 c6 45 ?? ?? c6 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Gendwnurl_BB_2147723181_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Gendwnurl.BB!bit"
        threat_id = "2147723181"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Gendwnurl"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "http://0c00.cc/0c_data.cc" wide //weight: 1
        $x_1_2 = {4d 00 53 00 58 00 4d 00 4c 00 32 00 2e 00 58 00 4d 00 4c 00 48 00 54 00 54 00 50 00 [0-16] 47 00 45 00 54 00}  //weight: 1, accuracy: Low
        $x_1_3 = {4f 00 70 00 65 00 6e 00 ?? ?? ?? ?? 53 00 65 00 6e 00 64 00 ?? ?? ?? ?? 72 00 65 00 61 00 64 00 79 00 53 00 74 00 61 00 74 00 65 00 ?? ?? ?? ?? 72 00 65 00 73 00 70 00 6f 00 6e 00 73 00 65 00 54 00 65 00 78 00 74 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Gendwnurl_BL_2147725159_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Gendwnurl.BL!bit"
        threat_id = "2147725159"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Gendwnurl"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sense.sdfgfdg.pw" wide //weight: 1
        $x_1_2 = "URLDownloadToFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Gendwnurl_BN_2147727044_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Gendwnurl.BN!bit"
        threat_id = "2147727044"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Gendwnurl"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {23 53 69 6e 67 6c 65 49 6e 73 74 61 6e 63 65 20 66 6f 72 63 65 0a 23 4e 6f 54 72 61 79 49 63 6f 6e 0a}  //weight: 1, accuracy: High
        $x_1_2 = {53 65 74 57 6f 72 6b 69 6e 67 44 69 72 2c 20 25 41 70 70 44 61 74 61 25 0a 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 2c 20 68 74 74 70 3a 2f 2f 37 38 2e 31 34 30 2e 32 32 30 2e 31 37 35 2f [0-32] 2c [0-16] 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Gendwnurl_BQ_2147727793_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Gendwnurl.BQ!bit"
        threat_id = "2147727793"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Gendwnurl"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {6c 00 65 00 77 00 64 00 2e 00 73 00 65 00 2f 00 [0-31] 2e 00 6a 00 70 00 67 00}  //weight: 3, accuracy: Low
        $x_1_2 = "DownloadData" wide //weight: 1
        $x_1_3 = "PODIZANJE" wide //weight: 1
        $x_1_4 = "injRun" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Gendwnurl_BT_2147729036_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Gendwnurl.BT!bit"
        threat_id = "2147729036"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Gendwnurl"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {40 00 2e 76 62 73 74 2d 81 b9 ?? ?? 40 00 2e 6a 73 00 74 21 83 f9 14 75 e2}  //weight: 1, accuracy: Low
        $x_1_2 = "c077dde6-6364-4419-acd2-b850581b8f64" ascii //weight: 1
        $x_1_3 = {42 81 c3 aa 00 00 00 83 f3 48 30 1a e2 f2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Gendwnurl_BU_2147729249_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Gendwnurl.BU!bit"
        threat_id = "2147729249"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Gendwnurl"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {62 69 74 73 61 64 6d 69 6e 20 2f 74 72 61 6e 73 66 65 72 20 6d 79 6a 6f 62 20 2f 64 6f 77 6e 6c 6f 61 64 20 2f 70 72 69 6f 72 69 74 79 20 68 69 67 68 20 68 74 74 70 3a 2f 2f 39 32 2e 36 33 2e 31 39 37 2e 36 30 2f 76 6e 63 2e 65 78 65 20 25 74 65 6d 70 25 5c [0-32] 2e 65 78 65 26 73 74 61 72 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

