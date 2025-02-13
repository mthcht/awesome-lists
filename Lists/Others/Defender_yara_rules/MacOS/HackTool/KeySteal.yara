rule HackTool_MacOS_KeySteal_2147747847_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/KeySteal!MTB"
        threat_id = "2147747847"
        type = "HackTool"
        platform = "MacOS: "
        family = "KeySteal"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "keystealDaemon/main.mm" ascii //weight: 1
        $x_1_2 = "de.linushenze.keySteal" ascii //weight: 1
        $x_1_3 = "fill_mach_port_array" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

