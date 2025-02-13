rule TrojanDownloader_PowerShell_Emotet_B_2147799324_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:PowerShell/Emotet.B"
        threat_id = "2147799324"
        type = "TrojanDownloader"
        platform = "PowerShell: "
        family = "Emotet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" ascii //weight: 1
        $x_1_2 = "http" ascii //weight: 1
        $x_1_3 = "foreach" ascii //weight: 1
        $x_1_4 = "invoke-webrequest" ascii //weight: 1
        $x_1_5 = "rundll32" ascii //weight: 1
        $x_1_6 = "start-process" ascii //weight: 1
        $x_1_7 = "iex " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

