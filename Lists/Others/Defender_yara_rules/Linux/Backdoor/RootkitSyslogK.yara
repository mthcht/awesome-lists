rule Backdoor_Linux_RootkitSyslogK_H_2147822795_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/RootkitSyslogK.H"
        threat_id = "2147822795"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "RootkitSyslogK"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "unhide_module)" ascii //weight: 1
        $x_1_2 = "is_invisible" ascii //weight: 1
        $x_1_3 = "syslogk.mod.c" ascii //weight: 1
        $x_2_4 = "/etc/rc-Zobk0jpi/PgSD93ql" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

