rule Trojan_PowerShell_Minerva_BE_2147935796_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/Minerva.BE!MTB"
        threat_id = "2147935796"
        type = "Trojan"
        platform = "PowerShell: "
        family = "Minerva"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= 'silentlycontinue'" wide //weight: 1
        $x_1_2 = ".DownloadFile('http" wide //weight: 1
        $x_1_3 = ".exe', 'c:" wide //weight: 1
        $x_1_4 = "sTart-pRoCEss 'c:" wide //weight: 1
        $x_1_5 = "Invoice.eXE" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

