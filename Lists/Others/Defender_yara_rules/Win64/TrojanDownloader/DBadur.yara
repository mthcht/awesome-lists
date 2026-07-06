rule TrojanDownloader_Win64_DBadur_AHB_2147972997_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/DBadur.AHB!MTB"
        threat_id = "2147972997"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "DBadur"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {78 6a 73 6a 6b 6a 64 73 6a 6a 64 2e 73 33 2e 61 70 2d 73 6f 75 74 68 65 61 73 74 2d 31 2e 61 6d 61 7a 6f 6e 61 77 73 2e 63 6f 6d 2f [0-10] 2e 7a 69 70}  //weight: 30, accuracy: Low
        $x_20_2 = "\\app_update.zip" ascii //weight: 20
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

