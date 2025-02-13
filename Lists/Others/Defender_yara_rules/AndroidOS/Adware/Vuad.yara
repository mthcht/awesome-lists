rule Adware_AndroidOS_Vuad_B_347603_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/Vuad.B!MTB"
        threat_id = "347603"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "Vuad"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {35 02 16 00 48 03 06 02 62 04 9e 26 94 05 02 01 48 04 04 05 b7 43 da 04 02 1f d4 44 fb 00 b7 43 8d 33 4f 03 06 02 d8 02 02 01 28 eb}  //weight: 1, accuracy: High
        $x_1_2 = {62 00 00 00 14 00 10 00 00 00 14 01 0f 00 00 00 90 00 00 01 94 00 00 01 3c 00 05 00 2a 00 53 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Adware_AndroidOS_Vuad_D_353625_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/Vuad.D!MTB"
        threat_id = "353625"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "Vuad"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cm/rltech/global" ascii //weight: 1
        $x_1_2 = "installApp" ascii //weight: 1
        $x_1_3 = "getPhoneData" ascii //weight: 1
        $x_1_4 = "getipaddress" ascii //weight: 1
        $x_1_5 = "getPhoneCallLog" ascii //weight: 1
        $x_1_6 = "getContactList" ascii //weight: 1
        $x_1_7 = "LockBootCompleteReceiver" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

