rule Trojan_AndroidOS_Smsspy_B_2147832361_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Smsspy.B"
        threat_id = "2147832361"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Smsspy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Lcom/vv/vodafone/post_data;" ascii //weight: 2
        $x_2_2 = "st24937.ispot.cc/payload5/" ascii //weight: 2
        $x_2_3 = "get_prim_phone" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Smsspy_C_2147835421_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Smsspy.C"
        threat_id = "2147835421"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Smsspy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "com.ngscript.smstest" ascii //weight: 2
        $x_2_2 = "5777990726BRI/?msg=" ascii //weight: 2
        $x_2_3 = "aHR0cHM6Ly9pb25pY2lvLmNvbS8=" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

