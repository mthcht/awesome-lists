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

