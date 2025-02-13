rule TrojanDownloader_MSIL_Triggre_A_2147900354_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Triggre.A!MTB"
        threat_id = "2147900354"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Triggre"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "cmd.exe /c ping" wide //weight: 2
        $x_2_2 = "1 -n 5 & copy" wide //weight: 2
        $x_2_3 = ".vbs" wide //weight: 2
        $x_2_4 = "1 -n 7 & del" wide //weight: 2
        $x_2_5 = "C:\\Windows\\Microsoft.NET\\Framework" wide //weight: 2
        $x_2_6 = "\\v4.0.30319" wide //weight: 2
        $x_1_7 = "StrReverse" ascii //weight: 1
        $x_1_8 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

