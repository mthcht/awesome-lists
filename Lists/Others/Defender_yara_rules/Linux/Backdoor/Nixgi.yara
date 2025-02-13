rule Backdoor_Linux_Nixgi_A_2147827560_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Nixgi.A!xp"
        threat_id = "2147827560"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Nixgi"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/tmp/xingyi_reverse_pid" ascii //weight: 1
        $x_1_2 = "/tmp/xingyi_bindshell_pid" ascii //weight: 1
        $x_1_3 = "/tmp/xingyi_reverse_port" ascii //weight: 1
        $x_1_4 = "/tmp/xingyi_bindshell_port" ascii //weight: 1
        $x_1_5 = "sw0rdm4n" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

