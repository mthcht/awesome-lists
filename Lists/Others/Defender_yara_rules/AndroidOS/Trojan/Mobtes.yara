rule Trojan_AndroidOS_Mobtes_A_2147812197_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Mobtes.A!xp"
        threat_id = "2147812197"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Mobtes"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "softotest@gmail.com" ascii //weight: 1
        $x_1_2 = "com.dreamstep.wDroidMovie" ascii //weight: 1
        $x_1_3 = "agilebinary/mobilemonitor/client/" ascii //weight: 1
        $x_1_4 = "ChangePasswordActivity" ascii //weight: 1
        $x_1_5 = "EventListActivity_SMS" ascii //weight: 1
        $x_1_6 = "/buy.php?upgrade=true&key=" ascii //weight: 1
        $x_2_7 = "biige.com" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_Mobtes_C_2147819330_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Mobtes.C!MTB"
        threat_id = "2147819330"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Mobtes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3a 02 3c 00 46 05 01 02 1a 06 ?? ?? 71 10 ?? ?? 06 00 0c 06 6e 20 ?? ?? 65 00 0c 05 46 06 05 03 46 05 05 04 71 10 ?? ?? 05 00 0a 05 23 57 ?? ?? b1 50 71 55 ?? ?? 09 37 6e 20 ?? ?? 78 00 0c 05 22 07 ?? ?? 70 30 ?? ?? a7 06 6e 10 ?? ?? 07 00 0a 06 39 06 05 00 6e 10 ?? ?? 07 00 22 06 ?? ?? 70 20 ?? ?? 76 00 6e 20 ?? ?? 56 00 6e 10 ?? ?? 06 00 d8 02 02 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {12 41 23 12 ?? ?? b1 10 12 03 71 51 ?? ?? 09 32 22 01 ?? ?? 70 20 ?? ?? 21 00 22 02 ?? ?? 70 20 ?? ?? 12 00 6e 10 ?? ?? 02 00 0a 01 23 12 ?? ?? b1 10 71 51 ?? ?? 09 32 22 01 ?? ?? 70 20 ?? ?? 21 00 1a 02 ?? ?? 71 10 ?? ?? 02 00 0c 02 6e 20 ?? ?? 21 00 0c 01 21 12 12 14 b1 42}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Mobtes_D_2147820420_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Mobtes.D!MTB"
        threat_id = "2147820420"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Mobtes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dn_ssl" ascii //weight: 1
        $x_1_2 = "bindRealApplication" ascii //weight: 1
        $x_1_3 = "getLeastCoins" ascii //weight: 1
        $x_1_4 = "loadXFile" ascii //weight: 1
        $x_1_5 = "decrypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_AndroidOS_Mobtes_AE_2147826955_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Mobtes.AE!MTB"
        threat_id = "2147826955"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Mobtes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "smsreplier.net/smsreply" ascii //weight: 1
        $x_1_2 = "trickerdata.php" ascii //weight: 1
        $x_1_3 = "://details?id=com.santa.iconosys" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Mobtes_E_2147827515_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Mobtes.E!MTB"
        threat_id = "2147827515"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Mobtes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "webcash.wooribank" ascii //weight: 1
        $x_1_2 = "phonemanager/services/bankwebservice?wsdl" ascii //weight: 1
        $x_1_3 = "cmd_start_bank" ascii //weight: 1
        $x_1_4 = "deletecalllog" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

