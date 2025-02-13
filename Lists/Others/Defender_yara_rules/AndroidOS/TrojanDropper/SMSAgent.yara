rule TrojanDropper_AndroidOS_SMSAgent_B_2147788383_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/SMSAgent.B!xp"
        threat_id = "2147788383"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "SMSAgent"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "aHR0cDovL3d3dy52cjlnYW1lLmNvbQ==" ascii //weight: 1
        $x_1_2 = "dilys.com.cn:9935/czzql/client/receive" ascii //weight: 1
        $x_1_3 = "lysms.de" ascii //weight: 1
        $x_1_4 = "web.idmzone.com" ascii //weight: 1
        $x_1_5 = "MobclickAgent.java " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

