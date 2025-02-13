rule Trojan_PowerShell_Flafisi_F_2147725886_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/Flafisi.F"
        threat_id = "2147725886"
        type = "Trojan"
        platform = "PowerShell: "
        family = "Flafisi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "(New-Object System.Net.WebClient).DownloadFile('" wide //weight: 10
        $x_1_2 = "FlashPlayer.jse'" wide //weight: 1
        $x_1_3 = "microsoft-patch.jse'" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

