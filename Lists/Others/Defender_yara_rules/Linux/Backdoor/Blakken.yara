rule Backdoor_Linux_Blakken_A_2147827829_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Blakken.A!xp"
        threat_id = "2147827829"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Blakken"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hlLjztq" ascii //weight: 1
        $x_1_2 = "npxXoudifFeEgGaACSncs" ascii //weight: 1
        $x_1_3 = "udpflood" ascii //weight: 1
        $x_1_4 = "tcpconnect" ascii //weight: 1
        $x_1_5 = "httpflood" ascii //weight: 1
        $x_1_6 = "dnsflood" ascii //weight: 1
        $x_1_7 = "Multihop attempted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

