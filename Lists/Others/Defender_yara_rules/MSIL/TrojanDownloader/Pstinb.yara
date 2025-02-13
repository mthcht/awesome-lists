rule TrojanDownloader_MSIL_Pstinb_A_2147690541_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Pstinb.A"
        threat_id = "2147690541"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Pstinb"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://pastebin.com/download.php?i=" wide //weight: 1
        $x_1_2 = {57 65 62 43 6c 69 65 6e 74 00 53 79 73 74 65 6d 2e 4e 65 74 00 44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 00 41 73 73 65 6d 62 6c 79 00 53 79 73 74 65 6d 2e 52 65 66 6c 65 63 74 69 6f 6e 00 43 6f 6e 76 65 72 74 00 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 00 4c 6f 61 64 00 67 65 74 5f 45 6e 74 72 79}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Pstinb_C_2147696617_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Pstinb.C"
        threat_id = "2147696617"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Pstinb"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Explorer1_Load" ascii //weight: 1
        $x_1_2 = "pastebin.com/download.php?i=sECyLgcB" wide //weight: 1
        $x_1_3 = "Users\\%userprofile%\\Music\\iexplore.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Pstinb_S_2147719410_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Pstinb.S!bit"
        threat_id = "2147719410"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Pstinb"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://pastebin.com/raw" ascii //weight: 1
        $x_1_2 = {61 64 64 5f 4c 6f 61 64 00 44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 00 41 70 70 44 6f 6d 61 69 6e 00 67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e 00 43 6f 6e 76 65 72 74 00 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Pstinb_T_2147719486_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Pstinb.T!bit"
        threat_id = "2147719486"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Pstinb"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 70 00 61 00 73 00 74 00 65 00 62 00 69 00 6e 00 2e 00 63 00 6f 00 6d 00 2f 00 72 00 61 00 77 00 2f 00 [0-32] 4c 00 6f 00 61 00 64 00 [0-4] 45 00 6e 00 74 00 72 00 79 00 50 00 6f 00 69 00 6e 00 74 00}  //weight: 2, accuracy: Low
        $x_1_2 = {52 65 76 65 72 73 65 00 43 6f 6e 76 65 72 74 00 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Pstinb_V_2147721492_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Pstinb.V!bit"
        threat_id = "2147721492"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Pstinb"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "JVUFFFOTFHAGLNQYEQFNYAWPIJ" wide //weight: 1
        $x_1_2 = {4d 44 35 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 00 54 72 69 70 6c 65 44 45 53 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72}  //weight: 1, accuracy: High
        $x_1_3 = {45 6e 74 72 79 50 6f 69 6e 74 00 54 68 72 65 61 64 53 74 61 72 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Pstinb_AE_2147726626_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Pstinb.AE!bit"
        threat_id = "2147726626"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Pstinb"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 00 1d 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 53 00 74 00 72 00 69 00 6e 00 67 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "aHR0cHM6Ly9wYXN0ZWJpbi5jb20" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Pstinb_AF_2147726996_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Pstinb.AF!bit"
        threat_id = "2147726996"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Pstinb"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://pastebin.com/raw/YZbvFwjX" ascii //weight: 1
        $x_1_2 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e 00 43 6f 6e 63 61 74 00 4c 6f 61 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

