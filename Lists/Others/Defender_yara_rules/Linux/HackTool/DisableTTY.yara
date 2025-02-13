rule HackTool_Linux_DisableTTY_A_2147766601_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/DisableTTY.A"
        threat_id = "2147766601"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "DisableTTY"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "echo " wide //weight: 1
        $x_1_2 = "Defaults !tty_tickets" wide //weight: 1
        $x_1_3 = "/etc/sudoers" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Linux_DisableTTY_B_2147766602_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/DisableTTY.B"
        threat_id = "2147766602"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "DisableTTY"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sed " wide //weight: 1
        $x_1_2 = "s/env_reset.*$/env_reset,timestamp_timeout=-1/" wide //weight: 1
        $x_1_3 = "/etc/sudoers" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

