rule Trojan_AndroidOS_Hypay_A_2147812485_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Hypay.A!xp"
        threat_id = "2147812485"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Hypay"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dmpush_lbx.jar" ascii //weight: 1
        $x_1_2 = "://182.92.65.247:7081/BaiduMv_Wang" ascii //weight: 1
        $x_1_3 = "DemoHeepayTest/SDK/SDKQuery.aspx" ascii //weight: 1
        $x_1_4 = "base64 -d > /tmp/$$.bin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

