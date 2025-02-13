rule Backdoor_Linux_ZHtrap_Do_2147795466_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/ZHtrap.Do!xp"
        threat_id = "2147795466"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "ZHtrap"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GET /sfkjdkfdj.txt" ascii //weight: 1
        $x_1_2 = "h5vwy6o32sdcsa5xurde35dqw5sf3cdsoeewqqxmhoyzsvar4u6ooead.onion" ascii //weight: 1
        $x_1_3 = "/bin/busybox" ascii //weight: 1
        $x_1_4 = "/bin/ZoneSec" ascii //weight: 1
        $x_1_5 = "/proc/cpuinfo" ascii //weight: 1
        $x_1_6 = "telnetadmin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

