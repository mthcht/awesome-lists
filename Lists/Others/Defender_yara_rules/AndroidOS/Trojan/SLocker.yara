rule Trojan_AndroidOS_SLocker_B_2147822250_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SLocker.B!MTB"
        threat_id = "2147822250"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 06 54 66 0a 00 54 66 0d 00 6e 10 25 00 06 00 0c 06 72 10 1c 00 06 00 0c 06 1a 07 ?? 00 6e 20 4a 00 76 00 0a 06 38 06 3e 00 07 06 54 66 0a 00 54 66 0f 00 07 07 54 77 0a 00 54 77 0e 00 72 20 23 00 76 00 22 06 08 00 07 6d 07 d6 07 d7 07 08 54 88 0a 00 54 88 0c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SLocker_C_2147826537_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SLocker.C!MTB"
        threat_id = "2147826537"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.fakedamage" ascii //weight: 1
        $x_1_2 = "gobluesms" ascii //weight: 1
        $x_1_3 = "gomisscallsms" ascii //weight: 1
        $x_1_4 = "goshakeme" ascii //weight: 1
        $x_1_5 = "com.misscallsms" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SLocker_G_2147826624_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SLocker.G!MTB"
        threat_id = "2147826624"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lcom/qqmagic/" ascii //weight: 1
        $x_1_2 = "getMailServerPort" ascii //weight: 1
        $x_1_3 = {47 72 65 79 57 6f 6c 66 00}  //weight: 1, accuracy: High
        $x_1_4 = {70 61 73 73 77 00}  //weight: 1, accuracy: High
        $x_1_5 = "createFloatView" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SLocker_E_2147827523_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SLocker.E!MTB"
        threat_id = "2147827523"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "com.sssp.MyAdmin" ascii //weight: 2
        $x_2_2 = "com.sssp.s" ascii //weight: 2
        $x_1_3 = "CjJJek41WWpN" ascii //weight: 1
        $x_1_4 = "resetPassword" ascii //weight: 1
        $x_1_5 = "logcat -v threadtime" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_SLocker_F_2147828399_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SLocker.F!MTB"
        threat_id = "2147828399"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "QQ:1500046461" ascii //weight: 1
        $x_1_2 = "QQMail:1500046461" ascii //weight: 1
        $x_1_3 = "incoming_number" ascii //weight: 1
        $x_1_4 = "isServiceRun" ascii //weight: 1
        $x_1_5 = "logcat -v threadtime" ascii //weight: 1
        $x_1_6 = "com.s.c.js" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

