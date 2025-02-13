rule Trojan_Linux_SuspectHostRecon_A_2147808249_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/SuspectHostRecon.A"
        threat_id = "2147808249"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "SuspectHostRecon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = ".1ma.xyz" wide //weight: 10
        $x_9_2 = "@/etc/passwd" wide //weight: 9
        $x_1_3 = "--data" wide //weight: 1
        $x_1_4 = "--post-data" wide //weight: 1
        $x_1_5 = "curl" wide //weight: 1
        $x_1_6 = "ping" wide //weight: 1
        $x_1_7 = "wget" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_9_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

