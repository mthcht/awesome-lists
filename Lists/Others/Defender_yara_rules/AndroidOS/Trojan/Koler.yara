rule Trojan_AndroidOS_Koler_BL_2147744861_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Koler.BL!MTB"
        threat_id = "2147744861"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Koler"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "http_identificationgeo_com_topnews_new_d_php_id_" ascii //weight: 2
        $x_2_2 = "file_android_asset_index_html" ascii //weight: 2
        $x_1_3 = "isMyServiceRunning" ascii //weight: 1
        $x_1_4 = "hideall" ascii //weight: 1
        $x_1_5 = "send_to_" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Koler_TA_2147745243_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Koler.TA!MSR"
        threat_id = "2147745243"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Koler"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {22 00 33 00 1c 01 ?? 03 70 30 da 00 40 01 6e 20 d6 00 04 00 5b 34 ?? 06 22 01 33 00 1c 02 ?? 03 70 30 da 00 41 02 5b 31 ?? 06 1c 01 ?? 03 70 20 ?? ?? 13 00 0a 01 39 01 07 00 54 31 87 06 6e 20 d6 00 14 00 6e 10 e0 00 05 00 0c 01 1a 02 06 0d 6e 20 ?? ?? 21 00 0a 01 38 01 07 00 54 31 ?? 06 6e 20 ?? ?? 41 00 0e 00}  //weight: 5, accuracy: Low
        $x_5_2 = {12 10 0f 00 40 00 69 02 ?? 06 54 20 ?? 06 54 21 ?? 06 6e 30 ?? ?? 02 01 22 00 ?? ?? 70 20 ?? ?? 20 00 5b 20 ?? 06 12 10 0f 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Koler_A_2147762599_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Koler.A!MTB"
        threat_id = "2147762599"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Koler"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "&brok=empty&u=3" ascii //weight: 1
        $x_1_2 = "com/lock/app/StartShowActivity" ascii //weight: 1
        $x_1_3 = "/send.php?v=" ascii //weight: 1
        $x_1_4 = "StartOvView" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Koler_B_2147828433_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Koler.B!MTB"
        threat_id = "2147828433"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Koler"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "rezultstroka" ascii //weight: 5
        $x_1_2 = "pininput" ascii //weight: 1
        $x_1_3 = "cardinput" ascii //weight: 1
        $x_1_4 = "accaunts" ascii //weight: 1
        $x_1_5 = "userDetails" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_Koler_B_2147828433_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Koler.B!MTB"
        threat_id = "2147828433"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Koler"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "gftube.org/send.php" ascii //weight: 1
        $x_1_2 = "response_serv" ascii //weight: 1
        $x_1_3 = "lockScreenReeiver" ascii //weight: 1
        $x_1_4 = "com/lock/app/StartOvView" ascii //weight: 1
        $x_1_5 = "sender_pin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Koler_H_2147897294_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Koler.H"
        threat_id = "2147897294"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Koler"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "6589y459gj4058rtgu" ascii //weight: 2
        $x_2_2 = "CHECK_FOR_UNLOCK" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

