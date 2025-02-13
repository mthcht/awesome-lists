rule Trojan_AndroidOS_Congur_A_2147744046_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Congur.A!MTB"
        threat_id = "2147744046"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Congur"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c29fe56fa59ab0db" ascii //weight: 1
        $x_1_2 = "Lcom/xcgdmmsj/BAH" ascii //weight: 1
        $x_1_3 = "com.xcgdmmsj.MyAdmin" ascii //weight: 1
        $x_1_4 = "lockNow" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Congur_A_2147851851_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Congur.A"
        threat_id = "2147851851"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Congur"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "VirusService$100000000" ascii //weight: 2
        $x_1_2 = "veil_lifted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

