rule Trojan_AndroidOS_BankBot_B_2147759464_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/BankBot.B!MTB"
        threat_id = "2147759464"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "BankBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "suspect a DoS attack based on hash collisions" ascii //weight: 1
        $x_1_2 = "requireinject" ascii //weight: 1
        $x_1_3 = "fasterxml/jackson/core/json/ByteSourceJsonBootstrapper" ascii //weight: 1
        $x_1_4 = "getSnapshot" ascii //weight: 1
        $x_1_5 = "recommended_card_view" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_AndroidOS_BankBot_C_2147759465_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/BankBot.C!MTB"
        threat_id = "2147759465"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "BankBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "enhancerecycle.java" ascii //weight: 1
        $x_1_2 = "javax/inject/Provider;" ascii //weight: 1
        $x_1_3 = "arrangeattack" ascii //weight: 1
        $x_1_4 = "setMacroOnAction" ascii //weight: 1
        $x_1_5 = "throwOnSetScreenshotButNoPiiAllowed" ascii //weight: 1
        $x_1_6 = "tortoiseevil" ascii //weight: 1
        $x_1_7 = "Persistent Cookie was expected" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

