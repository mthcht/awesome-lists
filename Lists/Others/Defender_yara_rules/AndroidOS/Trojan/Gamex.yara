rule Trojan_AndroidOS_Gamex_A_2147656637_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Gamex.A"
        threat_id = "2147656637"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Gamex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BuildConfig.java" ascii //weight: 1
        $x_1_2 = "TargetApi.java" ascii //weight: 1
        $x_1_3 = "inputex/index.php?s=/Interface/neiinter" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Gamex_A_2147656637_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Gamex.A"
        threat_id = "2147656637"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Gamex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "chmod 644 /system/app/ComAndroidSetting.apk" ascii //weight: 1
        $x_1_2 = "gamex/inset/BuildConfig" ascii //weight: 1
        $x_1_3 = "logos.png" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

