rule Backdoor_Linux_EwDoor_A_2147809150_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/EwDoor.A!MTB"
        threat_id = "2147809150"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "EwDoor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "killall -9 netflash >/dev/null 2>&1" ascii //weight: 1
        $x_1_2 = "/var/soc2_upgrade.lock" ascii //weight: 1
        $x_1_3 = "/etc/config/ew.conf" ascii //weight: 1
        $x_1_4 = "cp -f /var/tmp/.mnt/ewupdate /var/tmp/.mnt/ewstat" ascii //weight: 1
        $x_1_5 = "rm -f /var/tmp/.mnt/ewupdate" ascii //weight: 1
        $x_1_6 = "start_syn_flood" ascii //weight: 1
        $x_1_7 = "start_udp_flood" ascii //weight: 1
        $x_1_8 = "/tmp/.ewstat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

