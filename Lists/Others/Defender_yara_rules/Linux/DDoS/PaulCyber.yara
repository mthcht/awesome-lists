rule DDoS_Linux_PaulCyber_A_2147830764_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Linux/PaulCyber.A!xp"
        threat_id = "2147830764"
        type = "DDoS"
        platform = "Linux: Linux platform"
        family = "PaulCyber"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CyberWarrior" ascii //weight: 1
        $x_1_2 = "IISDDoS v1.0" ascii //weight: 1
        $x_1_3 = "ddos.ini" ascii //weight: 1
        $x_1_4 = "Usage: ./ddos <ip> [<number of servers> [<startline from serverlist>]]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

