rule HackTool_MacOS_Aircrack_A_2147745995_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/Aircrack.A!MTB"
        threat_id = "2147745995"
        type = "HackTool"
        platform = "MacOS: "
        family = "Aircrack"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/private/tmp/aircrack-ng" ascii //weight: 1
        $x_1_2 = "/usr/local/Cellar/aircrack-ng" ascii //weight: 1
        $x_1_3 = "SELECT pmk.PMK, passwd.passwd FROM pmk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_MacOS_Aircrack_B_2147747964_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/Aircrack.B!MTB"
        threat_id = "2147747964"
        type = "HackTool"
        platform = "MacOS: "
        family = "Aircrack"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "www.aircrack-ng.org" ascii //weight: 1
        $x_1_2 = "aircrack-ng.c" ascii //weight: 1
        $x_1_3 = "SELECT pmk.PMK, passwd.passwd FROM pmk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

