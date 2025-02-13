rule HackTool_MacOS_Intercep_I_2147743110_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/Intercep.I"
        threat_id = "2147743110"
        type = "HackTool"
        platform = "MacOS: "
        family = "Intercep"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 6e 74 65 72 63 65 70 74 65 72 2d 4e 47 [0-6] 5b 43 6f 6e 73 6f 6c 65 20 45 64 69 74 69 6f 6e 5d}  //weight: 1, accuracy: Low
        $x_1_2 = "sniff.su" ascii //weight: 1
        $x_1_3 = "sysctl -w net.inet.ip.forwarding=1 > /dev/null" ascii //weight: 1
        $x_1_4 = "Start Capturing" ascii //weight: 1
        $x_1_5 = "Start ARP Poisoning" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

