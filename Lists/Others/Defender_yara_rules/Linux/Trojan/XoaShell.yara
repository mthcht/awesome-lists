rule Trojan_Linux_XoaShell_G5_2147937215_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/XoaShell.G5"
        threat_id = "2147937215"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "XoaShell"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "s=" wide //weight: 2
        $x_2_2 = "&&i=" wide //weight: 2
        $x_2_3 = "&&hname=$(hostname)&&p=https://;curl -s -k " wide //weight: 2
        $x_2_4 = "$p$s/" wide //weight: 2
        $x_2_5 = "/$hname/$USER" wide //weight: 2
        $x_2_6 = "Authorization: $i" wide //weight: 2
        $x_2_7 = "sleep 0.8" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

