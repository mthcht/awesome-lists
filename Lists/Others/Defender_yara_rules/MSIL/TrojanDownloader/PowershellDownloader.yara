rule TrojanDownloader_MSIL_PowershellDownloader_RDA_2147835442_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/PowershellDownloader.RDA!MTB"
        threat_id = "2147835442"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PowershellDownloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/c powershell -EncodedCommand" wide //weight: 2
        $x_2_2 = "-ExclusionPath @($env:UserProfile,$env:SystemDrive)" wide //weight: 2
        $x_2_3 = "-ChildPath 'services64.exe'))" wide //weight: 2
        $x_1_4 = "Deepnude" ascii //weight: 1
        $x_1_5 = "5850a2b0-3717-49d0-b392-5a12a61351b9" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

