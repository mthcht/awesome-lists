rule Trojan_MacOS_SuspPersistentPFRuleMod_A_2147976464_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/SuspPersistentPFRuleMod.A"
        threat_id = "2147976464"
        type = "Trojan"
        platform = "MacOS: "
        family = "SuspPersistentPFRuleMod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "grep -ah screensharing /var/log/system.log" wide //weight: 1
        $x_1_2 = "cp /etc/pf.conf /etc/pf.conf.bak" wide //weight: 1
        $x_1_3 = "block drop in quick proto tcp from any to any port" wide //weight: 1
        $x_1_4 = "<key>RunAtLoad</key><true/>" wide //weight: 1
        $x_1_5 = "pfctl -f /etc/pf.conf" wide //weight: 1
        $x_1_6 = "chmod 644 /Library/LaunchDaemons/" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

