rule TrojanDownloader_Win32_Oceanmug_A_2147682176_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Oceanmug.A"
        threat_id = "2147682176"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Oceanmug"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {75 74 69 6c 6f 63 65 61 6e 2e 46 69 6c 65 44 6f 77 6e 6c 6f 61 64 65 72 00}  //weight: 2, accuracy: High
        $x_2_2 = {75 74 69 6c 6f 63 65 61 6e 2e 58 50 5f 50 72 6f 67 72 65 73 73 42 61 72 00}  //weight: 2, accuracy: High
        $x_2_3 = {75 00 74 00 69 00 6c 00 6f 00 63 00 65 00 61 00 6e 00 63 00 63 00 00 00}  //weight: 2, accuracy: High
        $x_1_4 = {26 00 75 00 73 00 72 00 5f 00 67 00 75 00 62 00 75 00 6e 00 3d 00 49 00 26 00 73 00 65 00 72 00 69 00 61 00 6c 00 6e 00 6f 00 3d 00 00 00}  //weight: 1, accuracy: High
        $x_2_5 = {48 00 4b 00 45 00 59 00 5f 00 43 00 55 00 52 00 52 00 45 00 4e 00 54 00 5f 00 55 00 53 00 45 00 52 00 5c 00 53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 75 00 74 00 69 00 6c 00 6f 00 63 00 65 00 61 00 6e 00 00 00}  //weight: 2, accuracy: High
        $x_6_6 = "121.78.93.185/~adcodecplus/utilocean/utilocean.html" wide //weight: 6
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_6_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_6_*) and 4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Oceanmug_B_2147682177_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Oceanmug.B"
        threat_id = "2147682177"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Oceanmug"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {75 74 69 6c 6f 63 65 61 6e 2e 46 69 6c 65 44 6f 77 6e 6c 6f 61 64 65 72 00}  //weight: 2, accuracy: High
        $x_2_2 = {75 74 69 6c 6f 63 65 61 6e 2e 58 50 5f 50 72 6f 67 72 65 73 73 42 61 72 00}  //weight: 2, accuracy: High
        $x_2_3 = {75 00 74 00 69 00 6c 00 6f 00 63 00 65 00 61 00 6e 00 63 00 63 00 00 00}  //weight: 2, accuracy: High
        $x_1_4 = {26 00 75 00 73 00 72 00 5f 00 67 00 75 00 62 00 75 00 6e 00 3d 00 49 00 26 00 73 00 65 00 72 00 69 00 61 00 6c 00 6e 00 6f 00 3d 00 00 00}  //weight: 1, accuracy: High
        $x_2_5 = {48 00 4b 00 45 00 59 00 5f 00 43 00 55 00 52 00 52 00 45 00 4e 00 54 00 5f 00 55 00 53 00 45 00 52 00 5c 00 53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 75 00 74 00 69 00 6c 00 6f 00 63 00 65 00 61 00 6e 00 00 00}  //weight: 2, accuracy: High
        $x_6_6 = "121.78.93.185/~adcodecplus/utilocean/utiloceanupfile.html" wide //weight: 6
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_6_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_6_*) and 4 of ($x_2_*))) or
            (all of ($x*))
        )
}

