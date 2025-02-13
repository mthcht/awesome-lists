rule DDoS_Linux_Sfloost_A_2147822864_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Linux/Sfloost.A!xp"
        threat_id = "2147822864"
        type = "DDoS"
        platform = "Linux: Linux platform"
        family = "Sfloost"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/delallmykkk" ascii //weight: 1
        $x_1_2 = "DnsFloodSendThread" ascii //weight: 1
        $x_1_3 = "rm -f /etc/rc.d/init.d/IptabLes" ascii //weight: 1
        $x_1_4 = "SynFloodBuildThread" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

