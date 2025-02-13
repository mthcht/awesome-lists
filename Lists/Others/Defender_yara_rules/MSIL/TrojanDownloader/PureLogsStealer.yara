rule TrojanDownloader_MSIL_PureLogsStealer_B_2147913635_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/PureLogsStealer.B!MTB"
        threat_id = "2147913635"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogsStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 0b 16 0c 2b ?? 06 08 06 08 91 07 08 07 8e 69 5d 91 61 d2 9c 08 17 58 0c 08 06 8e 69}  //weight: 2, accuracy: Low
        $x_2_2 = "AntiAnalysis" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

