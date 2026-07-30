rule Trojan_Linux_RondoDox_AMTB_2147967204_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/RondoDox!AMTB"
        threat_id = "2147967204"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "RondoDox"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rondo:345:once:%s %s.persisted" ascii //weight: 1
        $x_2_2 = "rondo2012@atomicmail.io" ascii //weight: 2
        $x_1_3 = "@reboot %s %s.persisted" ascii //weight: 1
        $x_1_4 = "npxXoudifFeEgGaACSncs[" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_RondoDox_A_2147974842_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/RondoDox.A"
        threat_id = "2147974842"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "RondoDox"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_6_1 = "/nuts/poop" wide //weight: 6
        $x_6_2 = "chmod" wide //weight: 6
        $x_2_3 = "nc" wide //weight: 2
        $x_2_4 = "curl" wide //weight: 2
        $x_2_5 = "wget" wide //weight: 2
        $x_1_6 = "http" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_6_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_6_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

