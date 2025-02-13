rule Trojan_PowerShell_Piychan_C_2147725392_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/Piychan.C"
        threat_id = "2147725392"
        type = "Trojan"
        platform = "PowerShell: "
        family = "Piychan"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "h(`$x in (0..$lwidth)){`$p=`$g.GetPixel(`$x,`$_)" wide //weight: 1
        $x_1_2 = "15)*16) -bor (`$p.G -band 15))}};IEX([System.Text.Encoding]::ASC" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

