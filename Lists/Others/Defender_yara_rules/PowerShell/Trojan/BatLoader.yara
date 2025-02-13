rule Trojan_PowerShell_BatLoader_D_2147834991_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/BatLoader.D"
        threat_id = "2147834991"
        type = "Trojan"
        platform = "PowerShell: "
        family = "BatLoader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "/?servername=msi" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

