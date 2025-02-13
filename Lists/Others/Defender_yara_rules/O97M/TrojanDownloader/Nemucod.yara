rule TrojanDownloader_O97M_Nemucod_PC_2147752332_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Nemucod.PC!MSR"
        threat_id = "2147752332"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Nemucod"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "28"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {68 74 74 70 [0-1] 3a 2f 2f [0-3] 2e [0-3] 2e [0-3] 2e [0-3] 2f 63 72 79 70 74 2e 64 6c 6c}  //weight: 10, accuracy: Low
        $x_10_2 = {43 3a 5c 72 6e 63 77 6e 65 72 5c [0-15] 2e 64 6c 6c 20 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72}  //weight: 10, accuracy: Low
        $x_2_3 = "URLMON" ascii //weight: 2
        $x_2_4 = "rundll32.exe" ascii //weight: 2
        $x_2_5 = "URLDownloadToFileA" ascii //weight: 2
        $x_2_6 = "ShellExecuteA" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

