rule TrojanDownloader_Win64_Bingom_PA_2147776054_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Bingom.PA!MTB"
        threat_id = "2147776054"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Bingom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\codebind.exe" ascii //weight: 1
        $x_1_2 = {6e 74 66 6c 78 2d 63 6f 6e 66 69 72 6d 61 74 69 6f 6e 2e 78 79 7a 2f [0-21] 2f 65 78 65 2f 73 65 74 68 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_3 = "ShellExecuteA" ascii //weight: 1
        $x_1_4 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

