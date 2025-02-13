rule TrojanDownloader_PowerShell_Gripogle_A_2147767492_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:PowerShell/Gripogle.A"
        threat_id = "2147767492"
        type = "TrojanDownloader"
        platform = "PowerShell: "
        family = "Gripogle"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "powershell.exe" wide //weight: 10
        $x_10_2 = "//iplogger.org/" wide //weight: 10
        $x_1_3 = "bitstransfer" wide //weight: 1
        $x_1_4 = "new-object" wide //weight: 1
        $x_1_5 = "invoke-webrequest" wide //weight: 1
        $x_1_6 = "::reflect" wide //weight: 1
        $x_1_7 = "::load" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

