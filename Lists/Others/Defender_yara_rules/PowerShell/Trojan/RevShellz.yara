rule Trojan_PowerShell_RevShellz_DA_2147961995_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/RevShellz.DA!MTB"
        threat_id = "2147961995"
        type = "Trojan"
        platform = "PowerShell: "
        family = "RevShellz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Net.Sockets.TCPClient($" wide //weight: 1
        $x_1_2 = ".GetStream(" wide //weight: 1
        $x_1_3 = ".StreamWriter($" wide //weight: 1
        $x_1_4 = ".Read($" wide //weight: 1
        $x_1_5 = ".GetString($" wide //weight: 1
        $x_1_6 = ".Length); $" wide //weight: 1
        $x_1_7 = "New-Object System.Byte[]" wide //weight: 1
        $x_1_8 = "; while ($" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

