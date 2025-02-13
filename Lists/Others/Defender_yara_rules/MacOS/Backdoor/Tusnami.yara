rule Backdoor_MacOS_Tusnami_A_2147783474_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/Tusnami.A!MTB"
        threat_id = "2147783474"
        type = "Backdoor"
        platform = "MacOS: "
        family = "Tusnami"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ":TSUNAMI <target> <secs>" ascii //weight: 1
        $x_1_2 = "syn flooder that will kill most network drivers" ascii //weight: 1
        $x_1_3 = "Killing pid %d" ascii //weight: 1
        $x_1_4 = "Downloads a file off the web and saves it onto the hd" ascii //weight: 1
        $x_1_5 = "Kills all current packeting" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

