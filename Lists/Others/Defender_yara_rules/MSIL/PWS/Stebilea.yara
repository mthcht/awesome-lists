rule PWS_MSIL_Stebilea_A_2147685576_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Stebilea.A"
        threat_id = "2147685576"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stebilea"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/C ping 1.1.1.1 -n 1 -w 10 > Nul & Del" wide //weight: 1
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_3 = "Steal psd's" wide //weight: 1
        $x_1_4 = "MISC PASSWORDS" wide //weight: 1
        $x_1_5 = "totalfuckshit" ascii //weight: 1
        $x_1_6 = "total_Fuck_CpInformtion" ascii //weight: 1
        $x_1_7 = "ftp_upload_NewxFuck" ascii //weight: 1
        $x_1_8 = "steam_fuck" ascii //weight: 1
        $x_1_9 = "attact_fuck" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

