rule TrojanDownloader_Win32_Fomish_2147582017_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Fomish"
        threat_id = "2147582017"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Fomish"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 74 74 70 3a 2f 2f 59 79 6c 2e 6d 6f 66 69 73 68 2e 63 6e 2f 77 65 76 6f 6f 2f 64 61 74 61 2f 64 61 74 61 ?? 2e 64 61 74}  //weight: 1, accuracy: Low
        $x_1_2 = "http://Yyl.mofish.cn/wevoo/data.dat" ascii //weight: 1
        $x_1_3 = "http://Yyl.mofish.cn/interFace/ActiveSeed.aspx" ascii //weight: 1
        $x_1_4 = "http://Yyl.mofish.cn/interface/SeedInstall.aspx" ascii //weight: 1
        $x_1_5 = {68 74 74 70 3a 2f 2f 59 79 6c 2e 6d 6f 66 69 73 68 2e 63 6e 2f 77 65 76 6f 6f 2f 6c 69 73 74 73 2f 32 30 30 ?? ?? ?? ?? ?? 2f 6c 69 73 74 2e 74 78 74}  //weight: 1, accuracy: Low
        $x_1_6 = {68 74 74 70 3a 2f 2f ?? ?? ?? 2e 6e 63 61 73 74 2e 63 6e 2f 6c 69 73 74 73 2f 32 30 30 ?? ?? ?? ?? ?? 2f 6c 69 73 74 2e 74 78 74}  //weight: 1, accuracy: Low
        $x_1_7 = "http://rep.eyeez.com/GetArea.aspx" ascii //weight: 1
        $x_1_8 = "ThirdSoft=%s&ID=%s&State=1&Mac=%s&InstallTime=%s" ascii //weight: 1
        $x_1_9 = "ThirdSoft=%s&State=1&Mac=%s" ascii //weight: 1
        $x_1_10 = "EXE_DL1" ascii //weight: 1
        $x_1_11 = "EXE_DL2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

