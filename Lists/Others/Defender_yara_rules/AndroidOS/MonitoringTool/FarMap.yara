rule MonitoringTool_AndroidOS_FarMap_A_350854_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/FarMap.A!MTB"
        threat_id = "350854"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "FarMap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PhoneNum_Sendto" ascii //weight: 1
        $x_1_2 = "fun.fMap" ascii //weight: 1
        $x_1_3 = "sPhoneNum_Askfor" ascii //weight: 1
        $x_1_4 = "/fmap/proc/vchk.asp?" ascii //weight: 1
        $x_1_5 = "regSendSMS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

