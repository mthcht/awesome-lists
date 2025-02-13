rule TrojanDownloader_Win32_Travnet_B_2147723813_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Travnet.B"
        threat_id = "2147723813"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Travnet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%snetmgr.lnk" ascii //weight: 1
        $x_1_2 = "%snetmgr.exe" ascii //weight: 1
        $x_1_3 = "NT-2012 Is Running!" ascii //weight: 1
        $x_1_4 = {55 70 6c 6f 61 64 52 61 74 65 00 00 44 6f 77 6e 43 6d 64 54 69 6d 65}  //weight: 1, accuracy: High
        $x_1_5 = "%sperf2012.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

