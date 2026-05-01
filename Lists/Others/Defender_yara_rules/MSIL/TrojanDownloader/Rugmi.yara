rule TrojanDownloader_MSIL_Rugmi_PAHW_2147968264_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Rugmi.PAHW!MTB"
        threat_id = "2147968264"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Cyrex_victim" wide //weight: 2
        $x_1_2 = "SELECT * FROM AntiVirusProduct" wide //weight: 1
        $x_1_3 = "winmgmts:\\\\.\\root\\SecurityCenter2" wide //weight: 1
        $x_2_4 = "remove AV Started" wide //weight: 2
        $x_2_5 = "/c schtasks /delete /f /tn" wide //weight: 2
        $x_1_6 = "injected  successfully" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

