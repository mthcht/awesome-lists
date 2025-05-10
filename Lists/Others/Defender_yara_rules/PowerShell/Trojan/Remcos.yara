rule Trojan_PowerShell_Remcos_RPA_2147941071_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/Remcos.RPA!MTB"
        threat_id = "2147941071"
        type = "Trojan"
        platform = "PowerShell: "
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "202"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe" wide //weight: 1
        $x_1_2 = "-ExecutionPolicy Bypass -windowstyle hidden -noexit" wide //weight: 1
        $x_100_3 = "[AppDomain]::CurrentDomain.Load([Convert]::FromBase64String((-join (Get-ItemProperty -LiteralPath 'HKCU:\\Software\\" wide //weight: 100
        $x_100_4 = "ForEach-Object {$_[-1..-($_.Length)]}))); [lol.lol]::lol('" wide //weight: 100
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

