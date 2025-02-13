rule TrojanDownloader_MSIL_Dedoal_B_2147696139_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Dedoal.B"
        threat_id = "2147696139"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dedoal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GBExistsV2" ascii //weight: 1
        $x_1_2 = "GBFileExists" ascii //weight: 1
        $x_1_3 = "ParseFileName" ascii //weight: 1
        $x_1_4 = "AntivirusInstalled" ascii //weight: 1
        $x_1_5 = "DetectAVResult" ascii //weight: 1
        $x_1_6 = "PostaAviso" ascii //weight: 1
        $x_1_7 = "CriaAlerta" ascii //weight: 1
        $x_1_8 = "MandarAviso" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

