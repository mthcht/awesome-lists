rule Trojan_AndroidOS_PhoniexRAT_K_2147903501_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/PhoniexRAT.K!MTB"
        threat_id = "2147903501"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "PhoniexRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "com/service/app/IndexACT" ascii //weight: 2
        $x_1_2 = "urlAdminPanel" ascii //weight: 1
        $x_1_3 = "swapsmsmenager" ascii //weight: 1
        $x_1_4 = "whileStartUpdateInection" ascii //weight: 1
        $x_1_5 = "startKingService" ascii //weight: 1
        $x_1_6 = "checkupdateInjection" ascii //weight: 1
        $x_1_7 = "ScreenStatus" ascii //weight: 1
        $x_1_8 = "goOffProtect" ascii //weight: 1
        $x_1_9 = "updateinjectandlistapps" ascii //weight: 1
        $x_1_10 = "updateBotParams" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

