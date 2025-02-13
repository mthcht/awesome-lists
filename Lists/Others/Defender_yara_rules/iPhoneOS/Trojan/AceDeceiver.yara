rule Trojan_iPhoneOS_AceDeceiver_B_2147750375_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:iPhoneOS/AceDeceiver.B!MTB"
        threat_id = "2147750375"
        type = "Trojan"
        platform = "iPhoneOS: "
        family = "AceDeceiver"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "tool.verify.i4.cn/toolCheck.xhtml" ascii //weight: 2
        $x_1_2 = "passwordkey123" ascii //weight: 1
        $x_1_3 = "xiufu.i4.cn" ascii //weight: 1
        $x_1_4 = "aisiweb_wallPaper" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_iPhoneOS_AceDeceiver_C_2147759848_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:iPhoneOS/AceDeceiver.C!MTB"
        threat_id = "2147759848"
        type = "Trojan"
        platform = "iPhoneOS: "
        family = "AceDeceiver"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hidden_extra_info" ascii //weight: 1
        $x_1_2 = "get_user_info" ascii //weight: 1
        $x_1_3 = "://url.i4.cn" ascii //weight: 1
        $x_1_4 = "member_saveLoginInfo.action" ascii //weight: 1
        $x_1_5 = "com.teiron.ppsync" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_iPhoneOS_AceDeceiver_D_2147787763_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:iPhoneOS/AceDeceiver.D!MTB"
        threat_id = "2147787763"
        type = "Trojan"
        platform = "iPhoneOS: "
        family = "AceDeceiver"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ios3.update.i4.cn/updateAppQuery.xhtml?%@&isAuth=%@&cid=%@&isjail=%@&toolversion=%@" ascii //weight: 2
        $x_1_2 = "HidesWhenStopped:" ascii //weight: 1
        $x_1_3 = "member_saveLoginInfo.action" ascii //weight: 1
        $x_1_4 = "com.teiron.ppsync" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

