rule TrojanSpy_AndroidOS_KSRemote_A_2147782746_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/KSRemote.A"
        threat_id = "2147782746"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "KSRemote"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ksremote.jar" ascii //weight: 2
        $x_2_2 = "EXPLOIT_ACTION" ascii //weight: 2
        $x_2_3 = "com.android.expl" ascii //weight: 2
        $x_2_4 = "compressInvaildRecordFile" ascii //weight: 2
        $x_1_5 = "Android_unkown" ascii //weight: 1
        $x_1_6 = "returnAutoJizhan" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

