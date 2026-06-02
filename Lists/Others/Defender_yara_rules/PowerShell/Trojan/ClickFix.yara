rule Trojan_PowerShell_ClickFix_AB_2147948541_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/ClickFix.AB!MTB"
        threat_id = "2147948541"
        type = "Trojan"
        platform = "PowerShell: "
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "invoke-webrequest" wide //weight: 1
        $x_1_2 = "iwr" wide //weight: 1
        $x_1_3 = "-useb" wide //weight: 1
        $x_10_4 = ".com/run/" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_PowerShell_ClickFix_EMA_2147970684_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/ClickFix.EMA!MTB"
        threat_id = "2147970684"
        type = "Trojan"
        platform = "PowerShell: "
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = ".click" wide //weight: 10
        $x_10_2 = "index.php" wide //weight: 10
        $x_1_3 = "Invoke-WebRequest" wide //weight: 1
        $x_1_4 = "GetRandomFileName()+'.exe" wide //weight: 1
        $x_1_5 = "-WindowStyle Hidden" wide //weight: 1
        $x_1_6 = "http" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

