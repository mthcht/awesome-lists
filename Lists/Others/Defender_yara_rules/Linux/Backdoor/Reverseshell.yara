rule Backdoor_Linux_Reverseshell_SR4_2147952967_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Reverseshell.SR4"
        threat_id = "2147952967"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Reverseshell"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "57"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "Usage: %s <reflect ip> <port>" ascii //weight: 50
        $x_2_2 = "/bin/sh" ascii //weight: 2
        $x_2_3 = "/bin/bash" ascii //weight: 2
        $x_1_4 = "socket" ascii //weight: 1
        $x_1_5 = "execl" ascii //weight: 1
        $x_1_6 = "execve" ascii //weight: 1
        $x_1_7 = "htons" ascii //weight: 1
        $x_1_8 = "inet_pton" ascii //weight: 1
        $x_1_9 = "dup2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_50_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

