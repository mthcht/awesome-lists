rule Trojan_AndroidOS_Cynos_A_2147805912_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Cynos.A"
        threat_id = "2147805912"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Cynos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SMSNUMBER_QIXINTONG" ascii //weight: 1
        $x_1_2 = "URL_UPSDKONLINETIMELOG" ascii //weight: 1
        $x_1_3 = "DEVICEINFOKEY_REGRETRYCOUNT" ascii //weight: 1
        $x_1_4 = "com.cyn0s.sldtkh" ascii //weight: 1
        $x_1_5 = "saveDeviceInfoValue2DB" ascii //weight: 1
        $x_1_6 = "/interior/getchargepointsms" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

