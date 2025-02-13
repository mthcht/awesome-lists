rule Trojan_Linux_Ellipsis_A_2147822419_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Ellipsis.A!xp"
        threat_id = "2147822419"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Ellipsis"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/var/log/everything.log" ascii //weight: 1
        $x_1_2 = "killall syslogd rsyslogd" ascii //weight: 1
        $x_1_3 = "/bin/rm -rf /tmp/..." ascii //weight: 1
        $x_1_4 = "dnsmasq tcpdump" ascii //weight: 1
        $x_1_5 = "maxflood" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

