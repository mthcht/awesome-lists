rule Trojan_MacOS_XSLCmd_A_2147745116_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/XSLCmd.A!MTB"
        threat_id = "2147745116"
        type = "Trojan"
        platform = "MacOS: "
        family = "XSLCmd"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/tmp/osname.log" ascii //weight: 1
        $x_1_2 = "/tmp/osver.log" ascii //weight: 1
        $x_1_3 = "screencapture -mx" ascii //weight: 1
        $x_1_4 = "compose.aspx?s=%4X%4X%4X%4X%4X%4X" ascii //weight: 1
        $x_1_5 = "%s/%04d%02d%02d_%02d%02d_%02d_keys.log" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

