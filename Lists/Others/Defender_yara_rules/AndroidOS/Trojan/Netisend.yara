rule Trojan_AndroidOS_Netisend_A_2147648477_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Netisend.A"
        threat_id = "2147648477"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Netisend"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "oneruan.com/netsend/nmsm.jsp?from=" ascii //weight: 1
        $x_1_2 = "eregi_replace" ascii //weight: 1
        $x_1_3 = "stopSelf" ascii //weight: 1
        $x_1_4 = "oneSoftDb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

