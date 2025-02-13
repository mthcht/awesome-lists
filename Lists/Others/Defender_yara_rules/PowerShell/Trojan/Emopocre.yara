rule Trojan_PowerShell_Emopocre_A_2147726206_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/Emopocre.A"
        threat_id = "2147726206"
        type = "Trojan"
        platform = "PowerShell: "
        family = "Emopocre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SHeLliD[1]+$SHELlid[13]+'x')( ( New-ObJEcT maNaGEment.aUtOmAtIoN.PScREDEnTIaL '" wide //weight: 1
        $x_1_2 = "%C^om^S^pEc% /V /c set %" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

