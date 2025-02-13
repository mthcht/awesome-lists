rule Trojan_AndroidOS_ScamApp_A_2147743810_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/ScamApp.A!MTB"
        threat_id = "2147743810"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "ScamApp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "Lcom/sirseni/simpleandroidwebviewexample/MainActivity;" ascii //weight: 4
        $x_2_2 = "sppromo.ru/apps.php?s=" ascii //weight: 2
        $x_2_3 = "zzwx.ru/test_area1?keyword=" ascii //weight: 2
        $x_1_4 = "setJavaScriptEnabled" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_ScamApp_B_2147752227_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/ScamApp.B!MTB"
        threat_id = "2147752227"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "ScamApp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {47 65 74 20 [0-4] 20 64 61 69 6c 79 20 70 61 79 74 6d 20 63 61 73 68 [0-4] 44 6f 77 6e 6c 6f 61 64 20 74 68 65 20 61 70 70}  //weight: 1, accuracy: Low
        $x_1_2 = "Rupees Free paytm cash just just by working on your phone" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

