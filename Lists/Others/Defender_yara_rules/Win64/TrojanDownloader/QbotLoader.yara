rule TrojanDownloader_Win64_QbotLoader_MD_2147846905_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/QbotLoader.MD!MTB"
        threat_id = "2147846905"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "QbotLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 75 72 6c 20 68 ?? 74 70 3a 2f 2f 31 30 39 2e 31 37 32 2e 34 35 2e 39 2f 4c 65 71 2f 31 35 20 2d 6f 20 63 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c 64 65 66 61 75 6c 74 2e 70 6e 67}  //weight: 1, accuracy: Low
        $x_1_2 = "rundll32 c:\\users\\public\\default.png,print" ascii //weight: 1
        $x_1_3 = "dllmain64.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

