rule Trojan_PowerShell_ClickFix_RR_2147948312_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/ClickFix.RR!MTB"
        threat_id = "2147948312"
        type = "Trojan"
        platform = "PowerShell: "
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "bypass" wide //weight: 1
        $x_1_3 = "JABhAD0AKABOAGUAdwAtAG8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_PowerShell_ClickFix_RRE_2147949458_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/ClickFix.RRE!MTB"
        threat_id = "2147949458"
        type = "Trojan"
        platform = "PowerShell: "
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "-split" wide //weight: 1
        $x_1_3 = "getstring" wide //weight: 1
        $x_1_4 = "(..)'|?{$_})|%{[Convert]::ToByte($_,16)}))" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

