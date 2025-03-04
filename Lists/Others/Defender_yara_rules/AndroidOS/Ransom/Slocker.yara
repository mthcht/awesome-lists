rule Ransom_AndroidOS_Slocker_A_2147766198_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:AndroidOS/Slocker.A!MTB"
        threat_id = "2147766198"
        type = "Ransom"
        platform = "AndroidOS: Android operating system"
        family = "Slocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AdminReceiver.Locker" ascii //weight: 1
        $x_1_2 = "system_update.apk" ascii //weight: 1
        $x_1_3 = "Commands.initialCommand" ascii //weight: 1
        $x_1_4 = "device_block" ascii //weight: 1
        $x_1_5 = "contactsListSend" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_AndroidOS_Slocker_B_2147766634_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:AndroidOS/Slocker.B!MTB"
        threat_id = "2147766634"
        type = "Ransom"
        platform = "AndroidOS: Android operating system"
        family = "Slocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Abrab16" ascii //weight: 3
        $x_1_2 = "admsurprises2" ascii //weight: 1
        $x_1_3 = "WodkTiva" ascii //weight: 1
        $x_1_4 = "setJavaScriptEnabled" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_AndroidOS_Slocker_C_2147815585_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:AndroidOS/Slocker.C!MTB"
        threat_id = "2147815585"
        type = "Ransom"
        platform = "AndroidOS: Android operating system"
        family = "Slocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "chenbibi.heima" ascii //weight: 1
        $x_1_2 = "lockNow" ascii //weight: 1
        $x_1_3 = "BlackCodeschenbb" ascii //weight: 1
        $x_1_4 = "MyQQ" ascii //weight: 1
        $x_1_5 = "FuckYou" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_AndroidOS_Slocker_D_2147820213_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:AndroidOS/Slocker.D!MTB"
        threat_id = "2147820213"
        type = "Ransom"
        platform = "AndroidOS: Android operating system"
        family = "Slocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.qianmo.root.MyAdmin" ascii //weight: 1
        $x_1_2 = "activiteDevice" ascii //weight: 1
        $x_1_3 = "resetPassword" ascii //weight: 1
        $x_1_4 = "Ladrt/ADRTLogCatReader" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

