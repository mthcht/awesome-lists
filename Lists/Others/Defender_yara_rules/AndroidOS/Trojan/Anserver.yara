rule Trojan_AndroidOS_Anserver_A_2147650236_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Anserver.A"
        threat_id = "2147650236"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Anserver"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "9CkOrC32uI327WBD7n__" ascii //weight: 1
        $x_1_2 = "7xBNzKFCzKFW9IiW" ascii //weight: 1
        $x_1_3 = "ewar01" ascii //weight: 1
        $x_1_4 = "warpeace" ascii //weight: 1
        $x_1_5 = "onGetApk_Install_version_id" ascii //weight: 1
        $x_1_6 = "8CBozKiTrtgdcxBNutkE8kMCzKFNHxMOKCRD" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

