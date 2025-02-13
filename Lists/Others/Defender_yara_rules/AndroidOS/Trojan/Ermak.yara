rule Trojan_AndroidOS_Ermak_A_2147901587_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Ermak.A!MTB"
        threat_id = "2147901587"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Ermak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hidesms" ascii //weight: 1
        $x_1_2 = "send_log_injects" ascii //weight: 1
        $x_1_3 = "openFake inject" ascii //weight: 1
        $x_1_4 = "killApplication admin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Ermak_B_2147919061_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Ermak.B!MTB"
        threat_id = "2147919061"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Ermak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ViewInjectionsad" ascii //weight: 1
        $x_1_2 = "send_log_injects" ascii //weight: 1
        $x_1_3 = "updateinjectandlistapps" ascii //weight: 1
        $x_1_4 = "downloadInjection" ascii //weight: 1
        $x_1_5 = "updateBotParams" ascii //weight: 1
        $x_1_6 = "updateBotSubInfo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

