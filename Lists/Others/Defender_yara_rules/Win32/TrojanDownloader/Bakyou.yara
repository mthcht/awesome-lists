rule TrojanDownloader_Win32_Bakyou_A_2147642636_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bakyou.A"
        threat_id = "2147642636"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bakyou"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\project\\OnlineSetup\\OnlineSetup\\Release\\Youbakinstaller" ascii //weight: 1
        $x_1_2 = {5c 4a 6a 6c 44 6f 77 6e 4c 6f 61 64 65 72 [0-26] 43 6c 6f 75 64 45 78 5f 6f 6e 6c 69 6e 65 73 65 74 75 70 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_3 = "PADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDING" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

