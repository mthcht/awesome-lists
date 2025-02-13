rule TrojanDownloader_AndroidOS_SAgent_A_2147826288_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:AndroidOS/SAgent.A!MTB"
        threat_id = "2147826288"
        type = "TrojanDownloader"
        platform = "AndroidOS: Android operating system"
        family = "SAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "api.nfjmfs.xyz" ascii //weight: 1
        $x_1_2 = "chaodaigan.com" ascii //weight: 1
        $x_1_3 = "jingongyinjiang.com" ascii //weight: 1
        $x_1_4 = "KefuWebViewActivity" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_AndroidOS_SAgent_B_2147838519_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:AndroidOS/SAgent.B!MTB"
        threat_id = "2147838519"
        type = "TrojanDownloader"
        platform = "AndroidOS: Android operating system"
        family = "SAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "iloveyou" ascii //weight: 1
        $x_1_2 = "ad_choices_container" ascii //weight: 1
        $x_1_3 = "CuService" ascii //weight: 1
        $x_1_4 = "KKReceiver" ascii //weight: 1
        $x_5_5 = {21 70 6e 10 ?? ?? 08 00 0a 01 12 02 12 03 12 04 35 03 14 00 34 14 03 00 12 04 48 05 07 03 6e 20 ?? ?? 48 00 0a 06 b7 65 8d 55 4f 05 07 03 d8 03 03 01 d8 04 04 01 28 ed}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

