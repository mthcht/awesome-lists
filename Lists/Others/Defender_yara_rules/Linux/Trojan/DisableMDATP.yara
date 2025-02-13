rule Trojan_Linux_DisableMDATP_A_2147793453_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/DisableMDATP.A"
        threat_id = "2147793453"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "DisableMDATP"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "systemctl stop mde_netfilter" wide //weight: 10
        $x_10_2 = "systemctl disable mde_netfilter" wide //weight: 10
        $x_10_3 = "systemctl stop mde_netfilter.socket" wide //weight: 10
        $x_10_4 = "systemctl disable mde_netfilter.socket" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

