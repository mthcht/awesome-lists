rule HackTool_AndroidOS_DroidSheep_A_2147782636_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:AndroidOS/DroidSheep.A!MTB"
        threat_id = "2147782636"
        type = "HackTool"
        platform = "AndroidOS: Android operating system"
        family = "DroidSheep"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HijackActivity" ascii //weight: 1
        $x_1_2 = "DroidSheep is listening for sessions" ascii //weight: 1
        $x_1_3 = "DROIDSHEEP_BLACKLIST" ascii //weight: 1
        $x_1_4 = "Spoofing was interrupted" ascii //weight: 1
        $x_1_5 = "arpspoof" ascii //weight: 1
        $x_1_6 = "authToHijack" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

