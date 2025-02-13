rule Trojan_AndroidOS_SpyRax_DS_2147809142_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyRax.DS!MTB"
        threat_id = "2147809142"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyRax"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sdcard/.fuck" ascii //weight: 1
        $x_1_2 = "SIMANDSDCARDINFO" ascii //weight: 1
        $x_1_3 = "Beging upload data..." ascii //weight: 1
        $x_1_4 = "GET_CALLLOGS" ascii //weight: 1
        $x_1_5 = "rm -r /data/data/com.tencent.mobileqq" ascii //weight: 1
        $x_1_6 = "GET_CONTCATS" ascii //weight: 1
        $x_1_7 = "emailbody.db" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

