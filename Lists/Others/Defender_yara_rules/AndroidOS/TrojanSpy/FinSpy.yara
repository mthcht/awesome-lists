rule TrojanSpy_AndroidOS_FinSpy_B_2147838331_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/FinSpy.B!MTB"
        threat_id = "2147838331"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "FinSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "www.malasi.cn/NoUseVersion.txt" ascii //weight: 1
        $x_1_2 = "getCardNumber" ascii //weight: 1
        $x_1_3 = "com.vipios" ascii //weight: 1
        $x_1_4 = "AnyuActivity" ascii //weight: 1
        $x_1_5 = "getShoujiInfo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

