rule TrojanDropper_AndroidOS_Sova_B_2147814685_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Sova.B!MTB"
        threat_id = "2147814685"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Sova"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "isEms" ascii //weight: 1
        $x_1_2 = "getApps" ascii //weight: 1
        $x_1_3 = "appHidden" ascii //weight: 1
        $x_1_4 = "updateinjects" ascii //weight: 1
        $x_1_5 = "2factor" ascii //weight: 1
        $x_1_6 = "deletecommand" ascii //weight: 1
        $x_1_7 = "injectlist" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule TrojanDropper_AndroidOS_Sova_C_2147816269_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Sova.C!MTB"
        threat_id = "2147816269"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Sova"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "injectlist" ascii //weight: 1
        $x_1_2 = "isEmulator" ascii //weight: 1
        $x_2_3 = {91 02 05 04 23 20 [0-5] 12 01 91 02 05 04 35 21 0f 00 62 02 [0-5] 90 03 04 01 4a 02 02 03 b7 62 8e 22 50 02 00 01 d8 01 01 01 28 f0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

