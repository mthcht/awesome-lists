rule Trojan_iPhoneOS_Conthie_A_2147771587_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:iPhoneOS/Conthie.A!MTB"
        threat_id = "2147771587"
        type = "Trojan"
        platform = "iPhoneOS: "
        family = "Conthie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://redvios.com:8085/" ascii //weight: 1
        $x_1_2 = "ladysizi.top:8081" ascii //weight: 1
        $x_1_3 = "startMonitoring" ascii //weight: 1
        $x_1_4 = "JYSystem/restInt/collect/postData" ascii //weight: 1
        $x_1_5 = "ABAddressBookCopyArrayOfAllPeople" ascii //weight: 1
        $x_1_6 = "attemptsToRecreateUploadTasksForBackgroundSessions" ascii //weight: 1
        $x_1_7 = "://180.215.254.23:9903/JYSystem/restInt/v3/collect/portal/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_iPhoneOS_Conthie_B_2147808041_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:iPhoneOS/Conthie.B!xp"
        threat_id = "2147808041"
        type = "Trojan"
        platform = "iPhoneOS: "
        family = "Conthie"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "attemptsToRecreateUploadTasksForBackgroundSessions" ascii //weight: 1
        $x_1_2 = "startMonitoring" ascii //weight: 1
        $x_1_3 = "ink.ushow.app.com.apps.agent381" ascii //weight: 1
        $x_1_4 = "107.151.194.116:8080" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_iPhoneOS_Conthie_E_2147837271_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:iPhoneOS/Conthie.E!MTB"
        threat_id = "2147837271"
        type = "Trojan"
        platform = "iPhoneOS: "
        family = "Conthie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {f4 4f be a9 fd 7b 01 a9 fd 43 00 91 e8 03 01 aa f3 03 00 aa 1f 20 03 d5 81 4d 1a 58 e0 03 08 aa ed 61 00 94 fd 03 1d aa fd 61 00 94 f4 03 00 aa 60 12 40 f9 1f 20 03 d5 81 59 1a 58 e6 61 00 94 fd 03 1d aa f6 61 00 94 9f 02 00 eb f3 17 9f 1a e7 61 00 94 e0 03 14 aa e5 61 00 94 e0 03 13 aa fd 7b 41 a9 f4 4f c2 a8 c0 03 5f d6}  //weight: 2, accuracy: High
        $x_1_2 = "startMonitoring" ascii //weight: 1
        $x_1_3 = "JYSystem/restInt/collect/postData" ascii //weight: 1
        $x_1_4 = "ABAddressBookCopyArrayOfAllPeople" ascii //weight: 1
        $x_1_5 = "attemptsToRecreateUploadTasksForBackgroundSessions" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

