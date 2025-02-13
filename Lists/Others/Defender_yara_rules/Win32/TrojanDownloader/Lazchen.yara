rule TrojanDownloader_Win32_Lazchen_A_2147638125_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Lazchen.A"
        threat_id = "2147638125"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazchen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ywYAAA==n7lsv0!x" ascii //weight: 1
        $x_1_2 = "bB!SP8*#WDMCAA==" ascii //weight: 1
        $x_1_3 = {50 46 60 45 6a 31 44 6b 61 4f 6b 09 6f 52 77 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

