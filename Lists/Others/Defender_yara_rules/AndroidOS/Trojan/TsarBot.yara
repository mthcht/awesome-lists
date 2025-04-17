rule Trojan_AndroidOS_TsarBot_A_2147939366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/TsarBot.A!MTB"
        threat_id = "2147939366"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "TsarBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/example/googleplayservice" ascii //weight: 1
        $x_1_2 = "ttps://xdjhgfgjh.run/injects/" ascii //weight: 1
        $x_1_3 = "ScreenCaptureService" ascii //weight: 1
        $x_1_4 = "password_inject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

