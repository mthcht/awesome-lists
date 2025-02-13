rule Worm_MacOS_Leap_A_2147746270_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MacOS/Leap.A!MTB"
        threat_id = "2147746270"
        type = "Worm"
        platform = "MacOS: "
        family = "Leap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/tmp/apphook_project/apphook.m" ascii //weight: 1
        $x_1_2 = "/tmp/latestpics.gz" ascii //weight: 1
        $x_1_3 = "x_initOutgoingWithSender:outgoingFile:chat:" ascii //weight: 1
        $x_1_4 = "x_anyActiveFileTransfers" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

