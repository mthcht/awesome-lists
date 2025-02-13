rule TrojanDownloader_Win32_Stemas_A_2147615807_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Stemas.gen!A"
        threat_id = "2147615807"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Stemas"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "MSVBVM60.DLL" ascii //weight: 1
        $x_1_2 = "novos" wide //weight: 1
        $x_1_3 = "linkcerto" ascii //weight: 1
        $x_1_4 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 73 00 69 00 73 00 74 00 65 00 6d 00 61 00 73 00 2e 00 75 00 6e 00 69 00 6c 00 65 00 73 00 74 00 65 00 6d 00 67 00 2e 00 62 00 72 00 2f 00 63 00 6f 00 6e 00 67 00 72 00 65 00 73 00 73 00 6f 00 5f 00 73 00 61 00 75 00 64 00 65 00 2f 00 69 00 6d 00 67 00 2f 00 [0-8] 2e 00 67 00 69 00 66 00}  //weight: 1, accuracy: Low
        $x_1_5 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

