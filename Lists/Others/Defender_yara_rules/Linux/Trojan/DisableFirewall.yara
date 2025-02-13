rule Trojan_Linux_DisableFirewall_A_2147773952_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/DisableFirewall.A"
        threat_id = "2147773952"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "DisableFirewall"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "SuSEfirewall2 stop" wide //weight: 10
        $x_10_2 = "reSuSEfirewall2 stop" wide //weight: 10
        $x_10_3 = "ufw stop" wide //weight: 10
        $x_10_4 = "ufw disable" wide //weight: 10
        $x_10_5 = "ufw logging off" wide //weight: 10
        $x_10_6 = "ufw prepend deny from " wide //weight: 10
        $x_10_7 = "systemctl stop ufw" wide //weight: 10
        $x_10_8 = "systemctl disable ufw" wide //weight: 10
        $x_10_9 = "systemctl mask ufw" wide //weight: 10
        $x_10_10 = "systemctl stop firewalld" wide //weight: 10
        $x_10_11 = "systemctl disable firewalld" wide //weight: 10
        $x_10_12 = "systemctl mask firewalld" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

