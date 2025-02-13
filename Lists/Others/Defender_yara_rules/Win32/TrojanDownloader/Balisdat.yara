rule TrojanDownloader_Win32_Balisdat_A_2147639508_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Balisdat.A"
        threat_id = "2147639508"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Balisdat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "NUR\\NOISREVTNERRUC\\SWODNIW\\TFOSORCIM\\ERAWTFOS" ascii //weight: 1
        $x_1_2 = {56 56 44 44 46 46 00}  //weight: 1, accuracy: High
        $x_1_3 = "Winssys.exe" ascii //weight: 1
        $x_1_4 = {68 74 74 70 3a 2f 2f [0-48] 2e 67 69 66 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Balisdat_B_2147652410_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Balisdat.B"
        threat_id = "2147652410"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Balisdat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {4f 6c 64 5f 43 75 72 72 65 6e 74 [0-16] 2e 43 75 72 72 65 6e 74 [0-16] 70 70 45 76 65 6e 74 73 5c 53 63 68 65 6d 65 73 5c 41 70 70 73 5c 45 78 70 6c 6f 72 65 72 5c 4e 61 76 69 67 61 74 69 6e 67 5c 4f 6c 64 5f 43 75 72 72 65 6e 74}  //weight: 10, accuracy: Low
        $x_10_2 = {74 61 b1 01 ba ?? ?? ?? ?? 8b 45 fc e8 ?? ?? ?? ?? 84 c0 74 4e 6a 01 b9 ?? ?? ?? ?? ba ?? ?? ?? ?? 8b 45 fc e8 ?? ?? ?? ?? eb 38}  //weight: 10, accuracy: Low
        $x_1_3 = {3a 5c 68 73 74 64 6f 63 73 2e 65 78 65 [0-5] 68 74 74 70 3a 2f 2f [0-32] 2f 6d 6e 2f 68 73 74 64 6f 63 73 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_4 = {3a 5c 49 6e 73 74 61 6c 6c 5f 56 43 2e 65 78 65 [0-5] 68 74 74 70 3a 2f 2f [0-37] 2f 6d 6e 2f 49 6e 73 74 61 6c 6c 5f 56 43 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_5 = {3a 5c 68 73 70 64 2e 65 78 65 [0-5] 68 74 74 70 3a 2f 2f [0-32] 2f 6d 6e 2f 68 73 70 64 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_6 = {3a 5c 77 69 6e 5f 68 73 74 2e 65 78 65 [0-5] 68 74 74 70 3a 2f 2f [0-37] 2f 77 69 6e 5f 68 73 74 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

