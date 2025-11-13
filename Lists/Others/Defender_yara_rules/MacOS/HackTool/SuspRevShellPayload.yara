rule HackTool_MacOS_SuspRevShellPayload_A1_2147957449_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/SuspRevShellPayload.A1"
        threat_id = "2147957449"
        type = "HackTool"
        platform = "MacOS: "
        family = "SuspRevShellPayload"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {40 00 80 d2 21 00 80 d2 02 00 80 d2 10 40 a0 d2 30 0c 80 f2}  //weight: 1, accuracy: High
        $x_1_2 = {01 00 00 d4}  //weight: 1, accuracy: High
        $x_1_3 = {10 40 a0 d2 50 0c 80 f2}  //weight: 1, accuracy: High
        $x_1_4 = {10 40 a0 d2 50 0b 80 f2}  //weight: 1, accuracy: High
        $x_1_5 = {10 40 a0 d2 70 07 80 f2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

