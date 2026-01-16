rule Trojan_PowerShell_Malilod_A_2147934183_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/Malilod.A"
        threat_id = "2147934183"
        type = "Trojan"
        platform = "PowerShell: "
        family = "Malilod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {29 00 2b 00 27 00 65 00 27 00 2b 00 27 00 78 00 27 00 29 00 28 00 [0-32] 20 00 2d 00 75 00 73 00 65 00 62 00 20 00 24 00}  //weight: 1, accuracy: Low
        $x_1_2 = ";new-alias printout c$($" wide //weight: 1
        $x_1_3 = ";.$([char](" wide //weight: 1
        $x_1_4 = ";foreach($" wide //weight: 1
        $x_1_5 = "+[char]($" wide //weight: 1
        $x_1_6 = "='ur'" wide //weight: 1
        $x_1_7 = ")l;$" wide //weight: 1
        $x_1_8 = "powershell.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

