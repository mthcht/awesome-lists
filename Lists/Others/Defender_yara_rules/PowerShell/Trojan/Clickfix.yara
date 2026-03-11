rule Trojan_PowerShell_Clickfix_SA_2147964476_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/Clickfix.SA!MTB"
        threat_id = "2147964476"
        type = "Trojan"
        platform = "PowerShell: "
        family = "Clickfix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "powershell.exe" wide //weight: 10
        $x_10_2 = "=Join-Path $env:TEMP" wide //weight: 10
        $x_10_3 = "GetRandomFileName()+'.exe')" wide //weight: 10
        $x_10_4 = "src=clickfix&" wide //weight: 10
        $x_10_5 = "index.php" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

