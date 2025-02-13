rule Backdoor_AndroidOS_Forav_A_2147826775_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/Forav.A!MTB"
        threat_id = "2147826775"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "Forav"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ib/csob/pkg/AAct" ascii //weight: 1
        $x_1_2 = "mylog_cmd" ascii //weight: 1
        $x_1_3 = "mylog_mess" ascii //weight: 1
        $x_1_4 = "mylog_hex_xor" ascii //weight: 1
        $x_1_5 = "/BNPi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

