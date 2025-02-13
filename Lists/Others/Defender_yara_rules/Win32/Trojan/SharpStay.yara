rule Trojan_Win32_SharpStay_SA_2147852149_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SharpStay.SA"
        threat_id = "2147852149"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SharpStay"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "action=ElevatedRegistryKey" wide //weight: 1
        $x_1_2 = "action=UserRegistryKey" wide //weight: 1
        $x_1_3 = "action=UserInitMprLogonScriptKey" wide //weight: 1
        $x_1_4 = "action=ElevatedUserInitKey" wide //weight: 1
        $x_1_5 = "action=ScheduledTask" wide //weight: 1
        $x_1_6 = "action=ListScheduledTasks" wide //weight: 1
        $x_1_7 = "action=ScheduledTaskAction" wide //weight: 1
        $x_1_8 = "action=SchTaskCOMHijack" wide //weight: 1
        $x_1_9 = "action=CreateService" wide //weight: 1
        $x_1_10 = "action=ListRunningServices" wide //weight: 1
        $x_1_11 = "action=WMIEventSub" wide //weight: 1
        $x_1_12 = "action=GetScheduledTaskCOMHandler" wide //weight: 1
        $x_1_13 = "action=JunctionFolder" wide //weight: 1
        $x_1_14 = "action=StartupDirectory" wide //weight: 1
        $x_1_15 = "action=NewLNK" wide //weight: 1
        $x_1_16 = "action=BackdoorLNK" wide //weight: 1
        $x_1_17 = "action=ListTaskNames" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

