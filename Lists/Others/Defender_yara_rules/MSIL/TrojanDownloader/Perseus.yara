rule TrojanDownloader_MSIL_Perseus_GG_2147745229_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Perseus.GG!MTB"
        threat_id = "2147745229"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Perseus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\Google\\Chrome\\" ascii //weight: 10
        $x_10_2 = "data.txt" ascii //weight: 10
        $x_10_3 = "svshost.exe" ascii //weight: 10
        $x_10_4 = "success" ascii //weight: 10
        $x_1_5 = "\\Verifone Data Viewer\\" ascii //weight: 1
        $x_1_6 = "Password incorrect!!!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            ((4 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_Perseus_MA_2147812735_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Perseus.MA!MTB"
        threat_id = "2147812735"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Perseus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Create__Instance" ascii //weight: 1
        $x_1_2 = "ToString" ascii //weight: 1
        $x_1_3 = "Dt_view_KeyDown" ascii //weight: 1
        $x_1_4 = "iremart.es/farmautils/ac1" wide //weight: 1
        $x_1_5 = "MemoryStream" ascii //weight: 1
        $x_1_6 = "DownloadData" ascii //weight: 1
        $x_1_7 = "check_antivirus_CheckedChanged" ascii //weight: 1
        $x_1_8 = "DebuggableAttribute" ascii //weight: 1
        $x_1_9 = "/c taskkill /IM Gwx.exe /F" wide //weight: 1
        $x_1_10 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

