rule Trojan_AndroidOS_Damon_A_2147815199_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Damon.A!MTB"
        threat_id = "2147815199"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Damon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "getDamonService" ascii //weight: 1
        $x_1_2 = "startDamonService" ascii //weight: 1
        $x_1_3 = "webservice.webxml.com.cn/webservices/DomesticAirline.asmx" ascii //weight: 1
        $x_1_4 = "installApk" ascii //weight: 1
        $x_1_5 = "downloadApk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

