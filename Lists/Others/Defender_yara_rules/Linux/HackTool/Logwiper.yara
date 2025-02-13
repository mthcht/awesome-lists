rule HackTool_Linux_Logwiper_A_2147816821_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Logwiper.A!xp"
        threat_id = "2147816821"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Logwiper"
        severity = "High"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/var/run/utmp" ascii //weight: 1
        $x_1_2 = "/tmp/UTMP.TMP" ascii //weight: 1
        $x_1_3 = "lastlog_clean" ascii //weight: 1
        $x_1_4 = "mig-logcleaner.c" ascii //weight: 1
        $x_1_5 = "chmod +x /tmp/mig.sh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

