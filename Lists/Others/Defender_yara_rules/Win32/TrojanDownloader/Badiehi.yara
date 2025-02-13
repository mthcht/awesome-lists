rule TrojanDownloader_Win32_Badiehi_PPS_2147709673_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Badiehi!PPS"
        threat_id = "2147709673"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Badiehi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {25 77 73 00 2d 00 75 00 3d 00 00 00 41 63 63 65 70 74 3a 20 2a 2f 2a}  //weight: 1, accuracy: High
        $x_1_2 = "Accept-Language: zh-cn" ascii //weight: 1
        $x_1_3 = "User-Agent: wget" ascii //weight: 1
        $x_10_4 = {71 71 70 63 6d 67 72 00 47 45 54 25 73 48 54 54 50 2f 31 2e 31}  //weight: 10, accuracy: High
        $x_10_5 = {83 c4 08 85 c0 74 0b 68 40 77 1b 00 ff}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

