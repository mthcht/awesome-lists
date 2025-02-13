rule Backdoor_Linux_Emperor_A_2147852241_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Emperor.A!MTB"
        threat_id = "2147852241"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Emperor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "emp3r0r" ascii //weight: 2
        $x_2_2 = "victimSize" ascii //weight: 2
        $x_1_3 = "UserAgent" ascii //weight: 1
        $x_1_4 = "syscall.socket" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

