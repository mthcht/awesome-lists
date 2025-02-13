rule Backdoor_AndroidOS_Smsflooder_GV_2147784113_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/Smsflooder.GV!MTB"
        threat_id = "2147784113"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "Smsflooder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/sdcard/.com.garena.cmdk/cms/.calldmp.txt" ascii //weight: 1
        $x_1_2 = "adminpasslock" ascii //weight: 1
        $x_1_3 = "dmpcalllog" ascii //weight: 1
        $x_1_4 = "dumpsms" ascii //weight: 1
        $x_1_5 = "Uploading SMS file..." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

