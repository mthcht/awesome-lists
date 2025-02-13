rule Trojan_AndroidOS_Mobfac_A_2147744513_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Mobfac.A!MSR"
        threat_id = "2147744513"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Mobfac"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://interface.kokmobi.com/newservice" ascii //weight: 1
        $x_1_2 = "/app/kok/TypeChannel" ascii //weight: 1
        $x_1_3 = "/app/kok/appChannel" ascii //weight: 1
        $x_1_4 = "/newbackDatas.action" ascii //weight: 1
        $x_1_5 = "/newgetApks.action" ascii //weight: 1
        $x_1_6 = "/newjsApk.action" ascii //weight: 1
        $x_1_7 = "/newopenOrSale.action" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

