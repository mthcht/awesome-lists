rule TrojanDownloader_Win64_Disfa_ARAC_2147901662_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Disfa.ARAC!MTB"
        threat_id = "2147901662"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Disfa"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {3a 2f 2f 77 65 74 68 73 6a 6a 73 64 66 2e 73 65 72 76 65 6d 69 6e 65 63 72 61 66 74 2e 6e 65 74 2f [0-63] 2e 65 78 65}  //weight: 2, accuracy: Low
        $x_2_2 = "URLDownloadToFile" ascii //weight: 2
        $x_2_3 = "%A_Startup%" ascii //weight: 2
        $x_2_4 = "&Window Spy" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

