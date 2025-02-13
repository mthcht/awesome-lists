rule Backdoor_iPhoneOS_Ftuscl_A_2147746261_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:iPhoneOS/Ftuscl.A!MTB"
        threat_id = "2147746261"
        type = "Backdoor"
        platform = "iPhoneOS: "
        family = "Ftuscl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SpyCallManagerSnapshot" ascii //weight: 1
        $x_1_2 = "var/.lsalcore/shares/" ascii //weight: 1
        $x_1_3 = "FxCall" ascii //weight: 1
        $x_1_4 = "sendCommandToSpyCallDaemon:cmdInfo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

