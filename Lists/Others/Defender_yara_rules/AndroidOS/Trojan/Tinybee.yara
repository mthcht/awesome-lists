rule Trojan_AndroidOS_Tinybee_A_2147793210_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Tinybee.A!MTB"
        threat_id = "2147793210"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Tinybee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TinybeeLogger" ascii //weight: 1
        $x_1_2 = "tinybee.savenumber.com" ascii //weight: 1
        $x_1_3 = "test.gall.me/tinybee/" ascii //weight: 1
        $x_1_4 = "It is a SMS Billing" ascii //weight: 1
        $x_1_5 = "da.mmarket.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

