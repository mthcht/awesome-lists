rule Trojan_AndroidOS_Gudex_A_2147896811_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Gudex.A"
        threat_id = "2147896811"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Gudex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "com.unreal.inj.MainService" ascii //weight: 2
        $x_2_2 = "/XAX 616" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Gudex_A_2147899829_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Gudex.A!MTB"
        threat_id = "2147899829"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Gudex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "api.legendsworld.in/Online/CrackSniper/asu.zip" ascii //weight: 1
        $x_1_2 = "com.CrackSniper.ui.Overlay" ascii //weight: 1
        $x_1_3 = "LobbyBypassP" ascii //weight: 1
        $x_1_4 = "ronakTRUE" ascii //weight: 1
        $x_1_5 = "RecorderFake" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

