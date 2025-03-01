rule Trojan_AndroidOS_Xloader_I1_2147787795_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Xloader.I1"
        threat_id = "2147787795"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Xloader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.u.SOGOU" ascii //weight: 1
        $x_1_2 = "Lren/ZHAN" ascii //weight: 1
        $x_1_3 = "Lcoi/QUXI" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Xloader_I2_2147787796_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Xloader.I2"
        threat_id = "2147787796"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Xloader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "lLoader" ascii //weight: 1
        $x_1_2 = "ccaddFlags" ascii //weight: 1
        $x_1_3 = "1bptlj0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Xloader_I3_2147787797_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Xloader.I3"
        threat_id = "2147787797"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Xloader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "==========wattefunkme..." ascii //weight: 1
        $x_1_2 = "extractDexs numberOfDexs:%d" ascii //weight: 1
        $x_1_3 = "shell createClassLoader step 3:%d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

