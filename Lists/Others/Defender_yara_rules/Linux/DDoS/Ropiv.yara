rule DDoS_Linux_Ropiv_A_2147830767_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Linux/Ropiv.A!xp"
        threat_id = "2147830767"
        type = "DDoS"
        platform = "Linux: Linux platform"
        family = "Ropiv"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "snmpscan.c" ascii //weight: 1
        $x_1_2 = "distortedX_SNMPSCAN" ascii //weight: 1
        $x_1_3 = "Vypor's SNMP" ascii //weight: 1
        $x_1_4 = "d.a.t.a.b.r.e.a.k" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

