rule HackTool_MacOS_SuspOSConfigChange_B1_2147932514_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/SuspOSConfigChange.B1"
        threat_id = "2147932514"
        type = "HackTool"
        platform = "MacOS: "
        family = "SuspOSConfigChange"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {5f 00 62 00 73 00 20 00 3e 00 2f 00 64 00 65 00 76 00 2f 00 6e 00 75 00 6c 00 6c 00 20 00 3b 00 20 00 63 00 68 00 6d 00 6f 00 64 00 20 00 37 00 37 00 37 00 [0-128] 2f 00 73 00 62 00 64 00 66 00 69 00 6c 00 65 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_MacOS_SuspOSConfigChange_D1_2147932515_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/SuspOSConfigChange.D1"
        threat_id = "2147932515"
        type = "HackTool"
        platform = "MacOS: "
        family = "SuspOSConfigChange"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "_bs >/dev/null ; trap" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

