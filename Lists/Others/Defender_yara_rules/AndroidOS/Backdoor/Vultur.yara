rule Backdoor_AndroidOS_Vultur_C_2147922952_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/Vultur.C!MTB"
        threat_id = "2147922952"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "Vultur"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vnc_enabled" ascii //weight: 1
        $x_1_2 = "NgrokDownloadWorker" ascii //weight: 1
        $x_1_3 = "VncSessionConfig" ascii //weight: 1
        $x_1_4 = "setClipToScreenEnabled" ascii //weight: 1
        $x_1_5 = "MediaUploadWorker" ascii //weight: 1
        $x_1_6 = "ScreenRecordWorker" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

