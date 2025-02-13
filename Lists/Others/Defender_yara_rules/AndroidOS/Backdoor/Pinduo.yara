rule Backdoor_AndroidOS_Pinduo_A_2147846764_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/Pinduo.A!MTB"
        threat_id = "2147846764"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "Pinduo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".pinduoduo.com/api/server" ascii //weight: 1
        $x_1_2 = "registActions" ascii //weight: 1
        $x_1_3 = "CmtZeusConfig" ascii //weight: 1
        $x_1_4 = "ScreenStateTracker" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

