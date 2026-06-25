rule Trojan_AndroidOS_Sturnus_A_2147972375_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Sturnus.A!MTB"
        threat_id = "2147972375"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Sturnus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "force_vnc" ascii //weight: 1
        $x_1_2 = "com.chrome.wupdater.vnc.ACTION_START" ascii //weight: 1
        $x_1_3 = "com.chrome.wupdater.vnc.EXTRA_SCALING" ascii //weight: 1
        $x_1_4 = "com.chrome.wupdater.vnc.EXTRA_FALLBACK_SCREEN_CAPTURE" ascii //weight: 1
        $x_1_5 = "com.chrome.wupdater.vnc.EXTRA_FILE_TRANSFER" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

