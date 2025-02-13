rule TrojanDownloader_Win32_Nuwar_B_2147595775_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Nuwar.B"
        threat_id = "2147595775"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Nuwar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/cntr.php?" ascii //weight: 2
        $x_2_2 = "svcp.csv" ascii //weight: 2
        $x_2_3 = "64.233" ascii //weight: 2
        $x_1_4 = "GetSystemDirectoryA" ascii //weight: 1
        $x_1_5 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_6 = "urlmon.dll" ascii //weight: 1
        $x_2_7 = "gagagaradio" ascii //weight: 2
        $x_2_8 = {77 69 6e 73 75 62 2e 78 6d 6c 00 57 69 6e 64 6f 77 73 53 75 62 56 65 72 73 69 6f 6e 00 00 55 52}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Nuwar_F_2147606290_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Nuwar.F"
        threat_id = "2147606290"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Nuwar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8b 45 cc 8b 4d d4 8b 55 c8 8b 04 81 2b 44 95 e4 8b 4d cc 8b 55 d4 89 04 8a}  //weight: 3, accuracy: High
        $x_3_2 = {55 8b ec 83 ec 4c 53 56 [0-112] c7 45 d0 ?? ?? 40 00 [0-64] 6a 06 59}  //weight: 3, accuracy: Low
        $x_1_3 = {68 b8 0b 00 00 ff 15}  //weight: 1, accuracy: High
        $x_2_4 = {8b 45 e0 2b 45 d8 3d b8 0b 00 00 73}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

