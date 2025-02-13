rule TrojanDownloader_Win32_Cadux_B_2147611083_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cadux.B"
        threat_id = "2147611083"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cadux"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 00 3a 00 5c 00 4d 00 61 00 73 00 74 00 65 00 72 00 5c 00 62 00 62 00 5f 00 73 00 6f 00 66 00 74 00 5c 00 6e 00 65 00 77 00 5c 00 62 00 62 00 5f 00 62 00 68 00 6f 00 5c 00 56 00 42 00 42 00 48 00 4f 00 2e 00 76 00 62 00 70 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {44 3a 5c 4d 61 73 74 65 72 5c 55 4e 49 5f 53 4f 46 54 5c 41 44 57 41 52 41 5c 62 68 6f 5c 76 62 62 68 6f 2e 74 6c 62 00}  //weight: 1, accuracy: High
        $x_1_3 = {67 65 74 73 6e 33 32 2e 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Cadux_A_2147615893_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cadux.A"
        threat_id = "2147615893"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cadux"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {67 65 74 73 6e 33 32 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_2 = {44 3a 5c 4d 61 73 74 65 72 5c 55 4e 49 5f 53 4f 46 54 5c 41 44 57 41 52 41 5c 62 68 6f 5c 76 62 62 68 6f 2e 74 6c 62 00}  //weight: 1, accuracy: High
        $x_1_3 = {44 00 3a 00 5c 00 4d 00 61 00 73 00 74 00 65 00 72 00 5c 00 62 00 62 00 5f 00 73 00 6f 00 66 00 74 00 5c 00 6e 00 6f 00 74 00 5f 00 65 00 73 00 74 00 5c 00 62 00 62 00 5f 00 62 00 68 00 6f 00 5c 00 56 00 42 00 42 00 48 00 4f 00 2e 00 76 00 62 00 70 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

