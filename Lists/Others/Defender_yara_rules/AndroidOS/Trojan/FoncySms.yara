rule Trojan_AndroidOS_FoncySms_A_2147652261_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FoncySms.A"
        threat_id = "2147652261"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FoncySms"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "not registred application" ascii //weight: 1
        $x_5_2 = "MagicSMSActivity.java" ascii //weight: 5
        $x_5_3 = "GEHEN SP" ascii //weight: 5
        $x_1_4 = "WUUT" ascii //weight: 1
        $x_1_5 = "STAR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_FoncySms_B_2147653263_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FoncySms.B"
        threat_id = "2147653263"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FoncySms"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "not registred application" ascii //weight: 1
        $x_1_2 = "AndroidBotActivity.java" ascii //weight: 1
        $x_1_3 = "SHELL_in" ascii //weight: 1
        $x_1_4 = "bot/files/rooted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

