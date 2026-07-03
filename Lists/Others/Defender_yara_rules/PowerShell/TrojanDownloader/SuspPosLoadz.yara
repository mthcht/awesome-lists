rule TrojanDownloader_PowerShell_SuspPosLoadz_ZC_2147972902_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:PowerShell/SuspPosLoadz.ZC!MTB"
        threat_id = "2147972902"
        type = "TrojanDownloader"
        platform = "PowerShell: "
        family = "SuspPosLoadz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-80] 24 00}  //weight: 1, accuracy: Low
        $x_1_2 = "($HOME+'/app'+'data/local" ascii //weight: 1
        $x_1_3 = "gc $" ascii //weight: 1
        $x_1_4 = "]; . ($" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

