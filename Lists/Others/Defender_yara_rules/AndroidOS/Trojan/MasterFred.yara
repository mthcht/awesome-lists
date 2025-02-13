rule Trojan_AndroidOS_MasterFred_A_2147830474_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/MasterFred.A"
        threat_id = "2147830474"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "MasterFred"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ChangeSmsDefaultAppActivity" ascii //weight: 1
        $x_1_2 = "android_loader_url" ascii //weight: 1
        $x_1_3 = "isNLEnabled" ascii //weight: 1
        $x_1_4 = "startLoaderActivity" ascii //weight: 1
        $x_1_5 = "AccessibilityEnableHintActivity" ascii //weight: 1
        $x_1_6 = "ActivityPreInstall" ascii //weight: 1
        $x_1_7 = "ActivityGetAccessability" ascii //weight: 1
        $x_1_8 = "start_work_me: thread: knocking..." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

