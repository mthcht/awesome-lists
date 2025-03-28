rule Trojan_Linux_FirewallOutHttpsBlock_PI2_2147937216_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/FirewallOutHttpsBlock.PI2"
        threat_id = "2147937216"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "FirewallOutHttpsBlock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "45"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "iptables " ascii //weight: 5
        $x_5_2 = "ip6tables " ascii //weight: 5
        $x_10_3 = " OUTPUT " ascii //weight: 10
        $x_10_4 = " -p tcp " ascii //weight: 10
        $x_10_5 = "port 443 " ascii //weight: 10
        $x_10_6 = "-j DROP" ascii //weight: 10
        $n_10_7 = "sport 443 " ascii //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((4 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Linux_FirewallOutHttpsBlock_PI3_2147937217_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/FirewallOutHttpsBlock.PI3"
        threat_id = "2147937217"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "FirewallOutHttpsBlock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "82"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "-A OUTPUT " ascii //weight: 20
        $x_20_2 = " -p tcp " ascii //weight: 20
        $x_20_3 = "port 443 " ascii //weight: 20
        $x_20_4 = "-j DROP" ascii //weight: 20
        $x_2_5 = "> /etc/iptables/rules.v4" ascii //weight: 2
        $x_2_6 = "> /etc/iptables/rules.v6" ascii //weight: 2
        $x_2_7 = "> /etc/sysconfig/iptables" ascii //weight: 2
        $x_2_8 = "> /etc/sysconfig/ip6tables" ascii //weight: 2
        $n_20_9 = "sport 443 " ascii //weight: -20
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((4 of ($x_20_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Linux_FirewallOutHttpsBlock_FU2_2147937218_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/FirewallOutHttpsBlock.FU2"
        threat_id = "2147937218"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "FirewallOutHttpsBlock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "ufw deny out to any port 443" ascii //weight: 10
        $x_10_2 = "ufw deny out https" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Linux_FirewallOutHttpsBlock_FU3_2147937219_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/FirewallOutHttpsBlock.FU3"
        threat_id = "2147937219"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "FirewallOutHttpsBlock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "82"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "ufw-user-output " ascii //weight: 20
        $x_20_2 = " -p tcp " ascii //weight: 20
        $x_20_3 = "port 443 " ascii //weight: 20
        $x_20_4 = "-j REJECT" ascii //weight: 20
        $x_2_5 = "> /etc/ufw/user.rules" ascii //weight: 2
        $n_20_6 = "sport 443 " ascii //weight: -20
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

