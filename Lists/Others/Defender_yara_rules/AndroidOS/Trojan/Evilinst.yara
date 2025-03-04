rule Trojan_AndroidOS_EvilInst_A_2147888996_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/EvilInst.A"
        threat_id = "2147888996"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "EvilInst"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "1dab9629-391f-47f3-9c76-e13dae0fee93" ascii //weight: 1
        $x_1_2 = "vnifood.com" ascii //weight: 1
        $x_1_3 = "onesignal5.modobomco.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_EvilInst_A_2147895678_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/EvilInst.A!MTB"
        threat_id = "2147895678"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "EvilInst"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vnitourist.com" ascii //weight: 1
        $x_1_2 = "vnifood.com" ascii //weight: 1
        $x_1_3 = "onesignal.modobomco.com" ascii //weight: 1
        $x_1_4 = "AfuService" ascii //weight: 1
        $x_1_5 = "actionAOC" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_EvilInst_K_2147896837_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/EvilInst.K"
        threat_id = "2147896837"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "EvilInst"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ConfirtinReceiver" ascii //weight: 2
        $x_2_2 = "SENDKWRO" ascii //weight: 2
        $x_2_3 = "FLAG_CONFIRM_KW1" ascii //weight: 2
        $x_2_4 = "NhanReceiver" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_EvilInst_B_2147902068_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/EvilInst.B!MTB"
        threat_id = "2147902068"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "EvilInst"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ConfirtinReceiver" ascii //weight: 1
        $x_1_2 = "FLAG_CONFIRM_KW1" ascii //weight: 1
        $x_1_3 = "NhanReceiver" ascii //weight: 1
        $x_1_4 = "apichecksubs.modobomco.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_EvilInst_C_2147902069_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/EvilInst.C!MTB"
        threat_id = "2147902069"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "EvilInst"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Flag_Mk_One" ascii //weight: 1
        $x_1_2 = "SENDSC" ascii //weight: 1
        $x_1_3 = "AfuService" ascii //weight: 1
        $x_1_4 = "modobomco.com/count-app" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_EvilInst_U_2147914250_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/EvilInst.U"
        threat_id = "2147914250"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "EvilInst"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SEND_HELLO_SAY" ascii //weight: 2
        $x_2_2 = "defaultKWApiTimeout" ascii //weight: 2
        $x_2_3 = "KEY_SAVE_SPR_DOWNLOAD_APK" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_EvilInst_E_2147923682_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/EvilInst.E!MTB"
        threat_id = "2147923682"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "EvilInst"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5b 01 30 0e 70 10 a1 15 00 00 0e 00}  //weight: 1, accuracy: High
        $x_1_2 = {22 00 5e 03 12 01 70 30 24 15 20 01 12 01 23 11 fc 03 6e 20 2d 0d 10 00 0e 00}  //weight: 1, accuracy: High
        $x_1_3 = "ggtlan/sub/MainActivity" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

