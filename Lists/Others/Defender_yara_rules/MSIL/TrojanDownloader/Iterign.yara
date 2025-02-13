rule TrojanDownloader_MSIL_Iterign_B_2147694865_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Iterign.B"
        threat_id = "2147694865"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Iterign"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\kick_me.exe" wide //weight: 1
        $x_1_2 = "\\Configuration.lnk" wide //weight: 1
        $x_1_3 = "C:\\Windows Update\\Console Security.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

