rule Trojan_Linux_SystemLogWiper_HA_2147836757_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/SystemLogWiper.HA"
        threat_id = "2147836757"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "SystemLogWiper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/var/adm/lastlog" ascii //weight: 2
        $x_2_2 = "/var/adm/pacct" ascii //weight: 2
        $x_2_3 = "/var/adm/utmp" ascii //weight: 2
        $x_2_4 = "/var/adm/wtmp" ascii //weight: 2
        $x_2_5 = "/var/log/utmp" ascii //weight: 2
        $x_2_6 = "/var/log/wtmp" ascii //weight: 2
        $x_2_7 = "/var/run/utmp" ascii //weight: 2
        $x_2_8 = "/var/log/lastlog" ascii //weight: 2
        $x_18_9 = "Alter lastlog entry" ascii //weight: 18
        $x_18_10 = "Blank lastlog for user" ascii //weight: 18
        $x_18_11 = "Erase acct entries" ascii //weight: 18
        $x_18_12 = "Erase last entry for user" ascii //weight: 18
        $x_18_13 = "Erase last entry on tty" ascii //weight: 18
        $x_18_14 = "Erase all usernames" ascii //weight: 18
        $x_18_15 = "Erase one username" ascii //weight: 18
        $x_18_16 = "wipe_acct" ascii //weight: 18
        $x_18_17 = "wipe_lastlog" ascii //weight: 18
        $x_18_18 = "wipe_wtmp" ascii //weight: 18
        $x_18_19 = "wipe system logs." ascii //weight: 18
        $x_18_20 = "wipe_utmp" ascii //weight: 18
        $x_20_21 = "wipe a [username]" ascii //weight: 20
        $x_20_22 = "wipe [ u|w|l|a ] " ascii //weight: 20
        $x_20_23 = "wipe [l,u,w] username" ascii //weight: 20
        $x_20_24 = "wipe l [username]" ascii //weight: 20
        $x_20_25 = "wipe u [username] " ascii //weight: 20
        $x_20_26 = "wipe w [username]" ascii //weight: 20
        $x_20_27 = "%s <username> <fixthings>" ascii //weight: 20
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_18_*) and 1 of ($x_2_*))) or
            ((2 of ($x_18_*))) or
            ((1 of ($x_20_*))) or
            (all of ($x*))
        )
}

