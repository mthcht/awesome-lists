rule Trojan_AndroidOS_Iconosys_A_2147783556_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Iconosys.A!MTB"
        threat_id = "2147783556"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Iconosys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "blackflyday.com/new" ascii //weight: 1
        $x_1_2 = "MeInJail" ascii //weight: 1
        $x_1_3 = "trickerdata.php" ascii //weight: 1
        $x_1_4 = "smsreplier.net/smsreply" ascii //weight: 1
        $x_1_5 = "buzzgeodata.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Iconosys_B_2147811835_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Iconosys.B!MTB"
        threat_id = "2147811835"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Iconosys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SendPhoneData" ascii //weight: 1
        $x_1_2 = "getPhoneNumbers" ascii //weight: 1
        $x_1_3 = "blackflyday.com/new/" ascii //weight: 1
        $x_1_4 = "smsreplier.net/smsreply" ascii //weight: 1
        $x_1_5 = "buzzgeodata.php" ascii //weight: 1
        $x_1_6 = "regandwelcome.php" ascii //weight: 1
        $x_1_7 = "SendPhoneGeoData" ascii //weight: 1
        $x_1_8 = "realphoneno" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Trojan_AndroidOS_Iconosys_A_2147812200_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Iconosys.A!xp"
        threat_id = "2147812200"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Iconosys"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "blackflyday.com" ascii //weight: 1
        $x_1_2 = "/FunnyJail/" ascii //weight: 1
        $x_1_3 = "trickerdata.php" ascii //weight: 1
        $x_1_4 = "smsreplier.net/smsreply" ascii //weight: 1
        $x_1_5 = "iconosysemail@rocketmail.com" ascii //weight: 1
        $x_1_6 = "://details?id=com.santa.iconosys" ascii //weight: 1
        $x_1_7 = "startCameraActivity" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_AndroidOS_Iconosys_C_2147829873_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Iconosys.C!MTB"
        threat_id = "2147829873"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Iconosys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "smsreplier.net/smsreply" ascii //weight: 1
        $x_1_2 = "trickerdata.php" ascii //weight: 1
        $x_1_3 = "phonedatanew.php" ascii //weight: 1
        $x_1_4 = "sendlicence.php" ascii //weight: 1
        $x_1_5 = "SendBkp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Iconosys_A_2147927140_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Iconosys.A"
        threat_id = "2147927140"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Iconosys"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SendAutoPhoneData" ascii //weight: 1
        $x_1_2 = "blackflyday.com/new/" ascii //weight: 1
        $x_1_3 = "smsreplier.com/fly" ascii //weight: 1
        $x_1_4 = "deals.dealbuzzer.net/iconosys.JPG" ascii //weight: 1
        $x_1_5 = "iconosysemail@rocketmail.com" ascii //weight: 1
        $x_1_6 = "SendToAutoServerTask" ascii //weight: 1
        $x_1_7 = "Top o' the mornin' and all day too! May the luck be shinin' on u! Happy St. Patrick's Day!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_AndroidOS_Iconosys_D_2147935642_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Iconosys.D!MTB"
        threat_id = "2147935642"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Iconosys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "market://details?id=com.santa.iconosys" ascii //weight: 1
        $x_1_2 = "newyearbuzzerstates" ascii //weight: 1
        $x_1_3 = "smsreplayierstates" ascii //weight: 1
        $x_1_4 = "tricktrackerstates" ascii //weight: 1
        $x_1_5 = "smsreplier.net/smsreply/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Iconosys_E_2147939800_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Iconosys.E!MTB"
        threat_id = "2147939800"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Iconosys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lcincodemayo/buzzer/iconosys/ChristmasTimer" ascii //weight: 1
        $x_1_2 = "chiristmascount11" ascii //weight: 1
        $x_1_3 = "newyearbuzzerstates" ascii //weight: 1
        $x_2_4 = "tricktrackerstates" ascii //weight: 2
        $x_2_5 = "drivereplaystates" ascii //weight: 2
        $x_2_6 = "santa_buttons_pressed" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

