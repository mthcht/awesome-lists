rule Ransom_PowerShell_FileFix_DZ_2147949391_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:PowerShell/FileFix.DZ!MTB"
        threat_id = "2147949391"
        type = "Ransom"
        platform = "PowerShell: "
        family = "FileFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "125"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "Powershell" wide //weight: 100
        $x_10_2 = "ransom" wide //weight: 10
        $x_10_3 = "Encrypt" wide //weight: 10
        $x_5_4 = " # " wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

