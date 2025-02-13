rule TrojanDownloader_Win32_Admedia_2147801391_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Admedia"
        threat_id = "2147801391"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Admedia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "http://www.ccnnic.com/download/" ascii //weight: 10
        $x_10_2 = "http://www.powernum123.com/download/" ascii //weight: 10
        $x_10_3 = "hwwpwwwwwwwpowernum123wcomwdownloadwpnxpwf" ascii //weight: 10
        $x_10_4 = {52 75 00 00 6f 6e 00 00 73 69 00 00 65 72 00 00 74 56 00 00 65 6e 00 00}  //weight: 10, accuracy: High
        $x_1_5 = "Software\\Dongtian\\" ascii //weight: 1
        $x_1_6 = "Windows\\CurrentVersion\\Policies\\Explorer\\Run" ascii //weight: 1
        $x_1_7 = "9153296582064149B0C6ED05018C9D07" ascii //weight: 1
        $x_1_8 = {6d 69 63 72 6f 61 70 6d 64 64 74 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

