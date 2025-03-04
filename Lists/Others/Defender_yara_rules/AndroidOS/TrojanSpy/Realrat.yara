rule TrojanSpy_AndroidOS_RealRat_A_2147811167_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/RealRat.A!MTB"
        threat_id = "2147811167"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "RealRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "INSTALLED RAT" ascii //weight: 1
        $x_1_2 = "sms_contacts" ascii //weight: 1
        $x_1_3 = "/receive.php" ascii //weight: 1
        $x_1_4 = "hidden_apk" ascii //weight: 1
        $x_1_5 = "all_sms" ascii //weight: 1
        $x_1_6 = "starter.txt" ascii //weight: 1
        $x_1_7 = "status" ascii //weight: 1
        $x_1_8 = "fata-iran.cf" ascii //weight: 1
        $x_1_9 = "remote-vip.tk" ascii //weight: 1
        $x_1_10 = "eblagh-sna.site" ascii //weight: 1
        $x_1_11 = "remote-best.tk" ascii //weight: 1
        $x_1_12 = "toprat.site" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule TrojanSpy_AndroidOS_RealRat_C_2147815489_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/RealRat.C!MTB"
        threat_id = "2147815489"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "RealRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_comand" ascii //weight: 1
        $x_1_2 = "_calllog" ascii //weight: 1
        $x_1_3 = "all-sms.txt" ascii //weight: 1
        $x_1_4 = "contact.txt" ascii //weight: 1
        $x_1_5 = "/panel.php" ascii //weight: 1
        $x_1_6 = "hideAppIcon" ascii //weight: 1
        $x_1_7 = "ir/Trol/fuZool" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule TrojanSpy_AndroidOS_RealRat_G_2147818677_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/RealRat.G!MTB"
        threat_id = "2147818677"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "RealRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "onStartCommand" ascii //weight: 2
        $x_2_2 = "_service_start" ascii //weight: 2
        $x_2_3 = "/receive.php" ascii //weight: 2
        $x_2_4 = "getHintHideIcon" ascii //weight: 2
        $x_1_5 = "kardarmanzel.gq" ascii //weight: 1
        $x_1_6 = "lordremote.xyz" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_RealRat_H_2147827265_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/RealRat.H!MTB"
        threat_id = "2147827265"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "RealRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lcom/pixo/rat/main" ascii //weight: 1
        $x_1_2 = "Lcom/reza/sh/deviceinfo" ascii //weight: 1
        $x_1_3 = "5.255.117.115" ascii //weight: 1
        $x_1_4 = "PNUploadFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_RealRat_H_2147827265_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/RealRat.H!MTB"
        threat_id = "2147827265"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "RealRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "42"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "ir.MrAventer.iptv" ascii //weight: 10
        $x_10_2 = "targetaddress" ascii //weight: 10
        $x_10_3 = "hideAppIcon" ascii //weight: 10
        $x_10_4 = "~test.test" ascii //weight: 10
        $x_10_5 = "PNSMS" ascii //weight: 10
        $x_10_6 = "isRunningOnEmulator" ascii //weight: 10
        $x_1_7 = "all_sms" ascii //weight: 1
        $x_1_8 = "app_list" ascii //weight: 1
        $x_1_9 = "hide_all" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 2 of ($x_1_*))) or
            ((5 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_RealRat_J_2147844102_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/RealRat.J"
        threat_id = "2147844102"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "RealRat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "_sendlargesms" ascii //weight: 2
        $x_2_2 = "/panelsetting/url.txt" ascii //weight: 2
        $x_2_3 = "type=newmessage&data=" ascii //weight: 2
        $x_2_4 = "Snake_phonelist.txt" ascii //weight: 2
        $x_2_5 = "_ussd_onreceiveussdresponse" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

