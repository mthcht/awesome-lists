rule Trojan_AndroidOS_Arsink_A_2147899023_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Arsink.A!MTB"
        threat_id = "2147899023"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Arsink"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SendNumb" ascii //weight: 1
        $x_1_2 = "getAllSms" ascii //weight: 1
        $x_1_3 = "_getAllContacts" ascii //weight: 1
        $x_1_4 = "_infodevice" ascii //weight: 1
        $x_1_5 = "getAllCallsHistoty" ascii //weight: 1
        $x_1_6 = "nikola/tesla/MainActivity" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Arsink_B_2147902250_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Arsink.B!MTB"
        threat_id = "2147902250"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Arsink"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "getAllCallsHistoty" ascii //weight: 1
        $x_1_2 = "_getAllContacts" ascii //weight: 1
        $x_1_3 = "com/ai/format/SpydroidActivity" ascii //weight: 1
        $x_1_4 = "_hack_sms_child_listener" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Arsink_C_2147902531_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Arsink.C!MTB"
        threat_id = "2147902531"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Arsink"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "remove/clothes/com" ascii //weight: 1
        $x_1_2 = "getAllCallsHistoty" ascii //weight: 1
        $x_1_3 = "calldmpp" ascii //weight: 1
        $x_1_4 = "haha_lol" ascii //weight: 1
        $x_1_5 = "_infodevice" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Arsink_E_2147913287_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Arsink.E!MTB"
        threat_id = "2147913287"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Arsink"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DarkRAT" ascii //weight: 1
        $x_1_2 = "_getAllContacts" ascii //weight: 1
        $x_1_3 = "User_App.txt" ascii //weight: 1
        $x_1_4 = "getAllCallsHistoty" ascii //weight: 1
        $x_1_5 = "mostafa/mostafa1/BackServices" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Arsink_F_2147918605_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Arsink.F!MTB"
        threat_id = "2147918605"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Arsink"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "arsinkRAT" ascii //weight: 1
        $x_1_2 = "User_App.txt" ascii //weight: 1
        $x_1_3 = "arsink.mp3" ascii //weight: 1
        $x_1_4 = "calldmpp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Arsink_R_2147921114_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Arsink.R!MTB"
        threat_id = "2147921114"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Arsink"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Phone Hack Data" ascii //weight: 1
        $x_1_2 = "getAllSms" ascii //weight: 1
        $x_1_3 = "Token.txt" ascii //weight: 1
        $x_1_4 = "haha_lol" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Arsink_G_2147923677_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Arsink.G!MTB"
        threat_id = "2147923677"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Arsink"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "getAcceptedIssuers" ascii //weight: 1
        $x_1_2 = "com/course/app/MainActivity" ascii //weight: 1
        $x_1_3 = "getAllCallsHistoty" ascii //weight: 1
        $x_1_4 = "SketchLogger" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Arsink_H_2147925839_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Arsink.H!MTB"
        threat_id = "2147925839"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Arsink"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "getAllCallsHistoty" ascii //weight: 1
        $x_2_2 = "Hacked By SisuryaOfficial" ascii //weight: 2
        $x_2_3 = "calldmpp" ascii //weight: 2
        $x_2_4 = "/storage/emulated/0/.HackedBySurya/" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Arsink_X_2147931872_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Arsink.X!MTB"
        threat_id = "2147931872"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Arsink"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EvilRat" ascii //weight: 1
        $x_1_2 = "DemonSen" ascii //weight: 1
        $x_1_3 = "TheEvil Camera" ascii //weight: 1
        $x_1_4 = "hide_app" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Arsink_I_2147932962_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Arsink.I!MTB"
        threat_id = "2147932962"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Arsink"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/DeathRat" ascii //weight: 1
        $x_1_2 = "_getAllContacts" ascii //weight: 1
        $x_1_3 = "getAllCallsHistoty" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

