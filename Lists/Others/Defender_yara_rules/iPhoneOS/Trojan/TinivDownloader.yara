rule Trojan_iPhoneOS_TinivDownloader_B_2147752826_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:iPhoneOS/TinivDownloader.B!MTB"
        threat_id = "2147752826"
        type = "Trojan"
        platform = "iPhoneOS: "
        family = "TinivDownloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/Applications/PPHelperNS.app/PPHelperNS" ascii //weight: 2
        $x_1_2 = "/tmp/.needuicache" ascii //weight: 1
        $x_1_3 = "/tmp/.pangu93loaded" ascii //weight: 1
        $x_1_4 = "://image.uc.cn/s/uae/g/26/ios_yueyutool/faq.html" ascii //weight: 1
        $x_1_5 = "cydia://url/file://%@" ascii //weight: 1
        $x_1_6 = "/Applications/Cydia.app" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_iPhoneOS_TinivDownloader_C_2147753618_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:iPhoneOS/TinivDownloader.C!MTB"
        threat_id = "2147753618"
        type = "Trojan"
        platform = "iPhoneOS: "
        family = "TinivDownloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "yingymmk=%@" ascii //weight: 3
        $x_1_2 = "//qm.kxnv.cn/api123.php" ascii //weight: 1
        $x_1_3 = "advertisingIdentifier" ascii //weight: 1
        $x_1_4 = "Desktop/zheng 2/zheng/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

