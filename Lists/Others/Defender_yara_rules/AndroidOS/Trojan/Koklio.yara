rule Trojan_AndroidOS_Koklio_A_2147744512_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Koklio.A!MSR"
        threat_id = "2147744512"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Koklio"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://w.w3c4f.com" ascii //weight: 1
        $x_1_2 = "http://w.woc4b.com" ascii //weight: 1
        $x_1_3 = "kokddlio" ascii //weight: 1
        $x_1_4 = "getRunningTasks" ascii //weight: 1
        $x_1_5 = "android.intent.action.TIME_TICK" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

