rule Trojan_MSIL_SharpStay_AY_2147981676_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SharpStay.AY!MTB"
        threat_id = "2147981676"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SharpStay"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SharpStay" ascii //weight: 2
        $x_1_2 = "set_Actions" ascii //weight: 1
        $x_1_3 = "action=ElevatedRegistryKey" ascii //weight: 1
        $x_1_4 = "action=UserRegistryKey" ascii //weight: 1
        $x_1_5 = "action=ScheduledTaskAction" ascii //weight: 1
        $x_1_6 = "action=BackdoorLNK" ascii //weight: 1
        $x_1_7 = "action=SchTaskCOMHijack" ascii //weight: 1
        $x_1_8 = "action=ListRunningServices" ascii //weight: 1
        $x_1_9 = "action=UserInitMprLogonScriptKey" ascii //weight: 1
        $x_1_10 = "action=ElevatedUserInitKey" ascii //weight: 1
        $x_1_11 = "action=ScheduledTask" ascii //weight: 1
        $x_1_12 = "action=CreateService" ascii //weight: 1
        $x_1_13 = "action=WMIEventSub" ascii //weight: 1
        $x_1_14 = "action=JunctionFolder" ascii //weight: 1
        $x_1_15 = "action=NewLNK" ascii //weight: 1
        $x_1_16 = "action=ListTaskNames" ascii //weight: 1
        $x_1_17 = "action=ListScheduledTasks" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

