rule Backdoor_Linux_Zyarinig_A_2147827830_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Zyarinig.A!xp"
        threat_id = "2147827830"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Zyarinig"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/tmp/.x" ascii //weight: 1
        $x_1_2 = "lifetime=5%20MIN" ascii //weight: 1
        $x_1_3 = "cgi-bin/supervisor/PwdGrp.cgi" ascii //weight: 1
        $x_1_4 = "action=del" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

