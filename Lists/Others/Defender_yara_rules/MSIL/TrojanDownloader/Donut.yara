rule TrojanDownloader_MSIL_Donut_ARAX_2147960403_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Donut.ARAX!MTB"
        threat_id = "2147960403"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Donut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "$99367ab5-bcd1-42c4-b145-86dfd5c65446" ascii //weight: 2
        $x_2_2 = "update.exe" wide //weight: 2
        $x_1_3 = "GetExecutingAssembly" ascii //weight: 1
        $x_1_4 = "HttpResponseMessage" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

