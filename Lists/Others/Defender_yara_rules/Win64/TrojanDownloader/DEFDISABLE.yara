rule TrojanDownloader_Win64_DEFDISABLE_DA_2147913277_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/DEFDISABLE.DA!MTB"
        threat_id = "2147913277"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "DEFDISABLE"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Add-MpPreference -ExclusionExtension" ascii //weight: 1
        $x_1_2 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_3 = {43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 54 00 65 00 6d 00 70 00 5c 00 [0-15] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_4 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 54 65 6d 70 5c [0-15] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_5 = "ShellExecuteA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

