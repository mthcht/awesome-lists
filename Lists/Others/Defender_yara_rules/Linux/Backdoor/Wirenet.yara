rule Backdoor_Linux_Wirenet_B_2147815787_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Wirenet.B!xp"
        threat_id = "2147815787"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Wirenet"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/tmp/nctf.txt" ascii //weight: 2
        $x_1_2 = "@reboot" ascii //weight: 1
        $x_1_3 = "crontab /tmp/nctf.txt 2>" ascii //weight: 1
        $x_1_4 = "Fin Wait" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

