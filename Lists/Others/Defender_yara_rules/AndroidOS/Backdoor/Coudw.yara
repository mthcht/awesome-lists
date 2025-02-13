rule Backdoor_AndroidOS_Coudw_A_2147806106_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/Coudw.A!MTB"
        threat_id = "2147806106"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "Coudw"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Lcom/clouds/server/ShCmd" ascii //weight: 2
        $x_1_2 = "shellcmd" ascii //weight: 1
        $x_1_3 = "system/bin/pm install -r" ascii //weight: 1
        $x_1_4 = "mount -o remount,rw /system" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

