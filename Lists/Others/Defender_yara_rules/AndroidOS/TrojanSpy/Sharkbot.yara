rule TrojanSpy_AndroidOS_Sharkbot_A_2147798999_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Sharkbot.A!MTB"
        threat_id = "2147798999"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Sharkbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 73 68 61 72 6b 65 64 00}  //weight: 1, accuracy: High
        $x_1_2 = "aa11_start_time" ascii //weight: 1
        $x_1_3 = "overlayClose" ascii //weight: 1
        $x_1_4 = "/MyReceiverSMS;" ascii //weight: 1
        $x_1_5 = "/aaOverlay;" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Sharkbot_C_2147814525_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Sharkbot.C"
        threat_id = "2147814525"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Sharkbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "51"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "service/ForceStopAccessibility" ascii //weight: 20
        $x_20_2 = "api/NotificationListener" ascii //weight: 20
        $x_2_3 = "adapter/VirusAdapter" ascii //weight: 2
        $x_2_4 = "api/shScanView" ascii //weight: 2
        $x_2_5 = "dialog/DialogAskPermission" ascii //weight: 2
        $x_2_6 = "lock/receiver/LockRestarterBroadcastReceiver" ascii //weight: 2
        $x_2_7 = "lock/services/LoadAppListService" ascii //weight: 2
        $x_1_8 = "statscodicefiscale.xyz" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Sharkbot_B_2147816665_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Sharkbot.B!MTB"
        threat_id = "2147816665"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Sharkbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "receiverSMS" ascii //weight: 1
        $x_1_2 = "overlayLife" ascii //weight: 1
        $x_1_3 = "sharked" ascii //weight: 1
        $x_2_4 = {3a 00 1b 00 6e 20 [0-5] 04 00 0a 02 d8 03 00 ff df 02 02 ?? 8e 22 50 02 01 00 3a 03 0e 00 d8 00 03 ff 6e 20 [0-5] 34 00 0a 02 df 02 02 ?? 8e 22 50 02 01 03 28 e6}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

