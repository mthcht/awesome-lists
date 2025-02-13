rule TrojanDownloader_Win32_Mytonel_A_2147695540_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Mytonel.A"
        threat_id = "2147695540"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Mytonel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {66 81 fd 00 fe 0f [0-16] 81 ?? 00 17 00 00}  //weight: 2, accuracy: Low
        $x_1_2 = "3dim700.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Mytonel_A_2147695540_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Mytonel.A"
        threat_id = "2147695540"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Mytonel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 66 00 66 00 66 00 2e 00 2f 10 10 00 2e 00 72 00 75 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {00 00 68 00 68 00 2e 00 6f 00 69 00 75 00 6e 00 62 00 73 00 69 00 75 00 6a 00 2e 00 72 00 75 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 00 67 00 67 00 67 00 2e 00 65 00 71 00 6e 00 61 00 64 00 73 00 6b 00 2e 00 72 00 75 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 00 74 00 74 00 74 00 2e 00 65 00 72 00 74 00 68 00 6a 00 69 00 6a 00 75 00 79 00 74 00 2e 00 72 00 75 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 00 67 00 74 00 2e 00 63 00 64 00 66 00 67 00 68 00 6b 00 6d 00 6a 00 2e 00 72 00 75 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 33 00 33 00 2f 00 0e 00 00 00 5c 00 53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 45 00 53 00 45 00 54 00 00 00 00 00 b0 04 02 00 ff ff ff ff 02 00 00}  //weight: 1, accuracy: Low
        $x_8_7 = {00 00 2f 00 70 00 72 00 6f 00 64 00 2e 00 70 00 68 00 70 00 3f 00 73 00 74 00 72 00 65 00 61 00 6d 00 49 00 64 00 3d 00 00 00}  //weight: 8, accuracy: High
        $x_8_8 = {00 00 2f 00 6e 00 6f 00 74 00 69 00 66 00 69 00 63 00 61 00 74 00 65 00 2e 00 70 00 68 00 70 00 3f 00 70 00 00 00}  //weight: 8, accuracy: High
        $x_8_9 = {00 00 69 00 63 00 65 00 32 00 5c 00 74 00 65 00 73 00 74 00 2d 00 72 00 65 00 73 00 75 00 6c 00 74 00 2e 00 6c 00 6f 00 67 00 00 00}  //weight: 8, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_8_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Mytonel_C_2147696843_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Mytonel.C"
        threat_id = "2147696843"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Mytonel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 00 69 00 63 00 61 00 74 00 65 00 2e 00 70 00 68 00 70 00 3f 00 70 00 72 00 6f 00 64 00 49 00 64 00 3d 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {69 00 63 00 65 00 32 00 5c 00 74 00 65 00 73 00 74 00 2d 00 72 00 65 00 73 00 75 00 6c 00 74 00 2e 00 6c 00 6f 00 67 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {2e 00 70 00 68 00 70 00 3f 00 73 00 74 00 72 00 65 00 61 00 6d 00 49 00 64 00 3d 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Mytonel_C_2147696843_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Mytonel.C"
        threat_id = "2147696843"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Mytonel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {73 00 74 00 72 00 65 00 61 00 6d 00 49 00 64 00 3d 00 00 00}  //weight: 2, accuracy: High
        $x_2_2 = {70 00 72 00 6f 00 64 00 49 00 64 00 3d 00 00 00}  //weight: 2, accuracy: High
        $x_2_3 = {73 00 74 00 61 00 74 00 75 00 73 00 3d 00 00 00}  //weight: 2, accuracy: High
        $x_5_4 = {5c 00 63 00 72 00 79 00 70 00 74 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 32 00 5c 00 74 00 65 00 73 00 74 00 2d 00 72 00 65 00 73 00 75 00 6c 00 74 00 2e 00 6c 00 6f 00 67 00 00 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Mytonel_D_2147696846_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Mytonel.D"
        threat_id = "2147696846"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Mytonel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 56 6a 08 68 09 02 00 00 51 ff d7 8b 56 ?? 6a 4f 6a 08 68 0a 02 00 00 52 ff d7 8b 46 ?? 6a 4b 6a 08 68 0b 02 00 00 50 ff d7 8b 4e ?? 6a 53 6a 08 68 0c 02 00 00 51 ff d7}  //weight: 1, accuracy: Low
        $x_1_2 = {75 20 ff d5 83 f8 20 75 19 ff d5 83 f8 20 75 12 68 f4 01 00 00 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {6a 00 68 80 ee 36 00 6a 02 51 ff d7 8b 56 1c 6a 00 68 80 ee 36 00 6a 03 52 ff d7}  //weight: 1, accuracy: High
        $x_2_4 = {00 57 61 74 63 68 44 65 73 6b 74 6f 70 20 46 69 6e 64 46 69 6c 65 00 00 00 2a 00 2e 00 2a 00 00 00 2a 00 2e 00 6c 00 6e 00 6b 00 00 00 43 57 61 74 63 68 44 65 73 6b 74 6f 70 20 52 75 6e 00}  //weight: 2, accuracy: High
        $x_2_5 = {00 44 4c 4c 69 73 74 2e 69 6e 69 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

