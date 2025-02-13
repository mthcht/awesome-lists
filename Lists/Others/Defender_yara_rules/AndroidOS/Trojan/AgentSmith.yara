rule Trojan_AndroidOS_AgentSmith_A_2147743955_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/AgentSmith.A!MTB"
        threat_id = "2147743955"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "AgentSmith"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "com.infectionapk.patchMain" ascii //weight: 3
        $x_3_2 = "resa.data.encry" ascii //weight: 3
        $x_3_3 = "adsdk.zip" ascii //weight: 3
        $x_1_4 = "Lcom/jio/jioplay/tv/application/JioTVApplication" ascii //weight: 1
        $x_1_5 = "Lcom/lenovo/anyshare/AnyShareApp;" ascii //weight: 1
        $x_1_6 = "Lcom/flipkart/android/init/FlipkartApplication" ascii //weight: 1
        $x_1_7 = "Lcom/whatsapp/AppShell;" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

