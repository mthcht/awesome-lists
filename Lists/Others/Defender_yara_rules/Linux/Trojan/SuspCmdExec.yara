rule Trojan_Linux_SuspCmdExec_LI1_2147967184_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/SuspCmdExec.LI1"
        threat_id = "2147967184"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "SuspCmdExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "ATTACKER_IP=" wide //weight: 10
        $x_10_2 = "RSH_PORT=" wide //weight: 10
        $x_10_3 = "METERPRETER_READY=" wide //weight: 10
        $x_10_4 = "SHELL_PORT=" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

