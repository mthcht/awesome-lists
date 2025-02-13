rule TrojanSpy_AndroidOS_Flubot_D_2147786800_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Flubot.D!MTB"
        threat_id = "2147786800"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Flubot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {12 02 35 12 27 00 14 04 84 a2 89 00 b1 84 48 08 03 02 14 09 8a 52 02 00 b0 96 dc 09 02 03 48 09 07 09 14 0a 12 5f 0d 00 b3 4a 91 04 06 0a b7 98 8d 88 4f 08 05 02 14 08 78 18 0b 00 93 09 04 06 b1 98 d8 02 02 01 01 6b 01 46 01 84 01 b8 28 da 13 01 32 00 35 10 0a 00 14 01 38 44 01 00 93 01 04 01 d8 00 00 01 28 f5 22 00 ?? ?? 70 20 ?? ?? 50 00 11 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Flubot_D_2147826106_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Flubot.D"
        threat_id = "2147826106"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Flubot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AmiDefaultSms" ascii //weight: 1
        $x_1_2 = "AutoAcceptPerms" ascii //weight: 1
        $x_1_3 = "CONTACT_TAB_POS" ascii //weight: 1
        $x_1_4 = "GetContactListUpload" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

