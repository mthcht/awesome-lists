rule Trojan_AndroidOS_Placms_A_2147782424_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Placms.A!MTB"
        threat_id = "2147782424"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Placms"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "mm_pay" ascii //weight: 1
        $x_1_2 = {4c 63 6f 6d [0-20] 50 61 79 53 74 61 74 75 73}  //weight: 1, accuracy: Low
        $x_1_3 = "debug_boot_pay" ascii //weight: 1
        $x_1_4 = "IscheckNumber" ascii //weight: 1
        $x_1_5 = "sp/sendnum.xml" ascii //weight: 1
        $x_1_6 = "KILL SMS IS OK" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

