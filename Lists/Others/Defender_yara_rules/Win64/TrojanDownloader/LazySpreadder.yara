rule TrojanDownloader_Win64_LazySpreadder_VGA_2147967899_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/LazySpreadder.VGA!MTB"
        threat_id = "2147967899"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "LazySpreadder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "powershell.exe -Command \"Add-MpPreference -ExclusionPath" ascii //weight: 1
        $x_1_2 = {3a 2f 2f 38 30 2e 32 35 33 2e 32 34 39 2e 31 36 39 3a 35 30 30 30 2f [0-32] 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

