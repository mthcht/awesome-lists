rule Trojan_PowerShell_SuspPosLoadz_ZA_2147972900_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/SuspPosLoadz.ZA!MTB"
        threat_id = "2147972900"
        type = "Trojan"
        platform = "PowerShell: "
        family = "SuspPosLoadz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "[string]$" ascii //weight: 1
        $x_1_2 = "iwr $" ascii //weight: 1
        $x_1_3 = "-UseBasicParsing;start $" ascii //weight: 1
        $x_1_4 = "powershell" ascii //weight: 1
        $x_1_5 = {68 00 74 00 74 00 70 00 [0-255] 2e 00 6a 00 73 00}  //weight: 1, accuracy: Low
        $x_1_6 = "$(Get-Location).tostring() +" ascii //weight: 1
        $x_1_7 = "$(Get-ChildItem" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_PowerShell_SuspPosLoadz_ZB_2147972901_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/SuspPosLoadz.ZB!MTB"
        threat_id = "2147972901"
        type = "Trojan"
        platform = "PowerShell: "
        family = "SuspPosLoadz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "&&set " ascii //weight: 1
        $x_1_2 = "--headless" ascii //weight: 1
        $x_1_3 = ";ge -f http" ascii //weight: 1
        $x_1_4 = "V:ON /c \"set" ascii //weight: 1
        $x_1_5 = "([string]$" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

