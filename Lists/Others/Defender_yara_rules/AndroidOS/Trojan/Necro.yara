rule Trojan_AndroidOS_Necro_A_2147759371_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Necro.A!MTB"
        threat_id = "2147759371"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Necro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "useStartNotify" ascii //weight: 1
        $x_1_2 = "useFullInject" ascii //weight: 1
        $x_1_3 = "Lsdk/nicro/web" ascii //weight: 1
        $x_1_4 = "webadlist" ascii //weight: 1
        $x_1_5 = "executedSearchUrls" ascii //weight: 1
        $x_1_6 = "Debug.webExec" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

