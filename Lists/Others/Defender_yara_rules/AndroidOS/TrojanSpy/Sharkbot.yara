rule TrojanSpy_AndroidOS_SharkBot_D_2147816688_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SharkBot.D!MTB"
        threat_id = "2147816688"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SharkBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "service/ForceStopAccessibility" ascii //weight: 2
        $x_2_2 = "adapter/VirusAdapter" ascii //weight: 2
        $x_2_3 = "lock/receiver/LockRestarterBroadcastReceiver" ascii //weight: 2
        $x_1_4 = "lock/services/LoadAppListService" ascii //weight: 1
        $x_1_5 = "sigmastats.xyz" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SharkBot_D_2147816688_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SharkBot.D!MTB"
        threat_id = "2147816688"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SharkBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {35 21 31 00 52 62 ?? ?? d8 02 02 01 d4 22 00 01 59 62 ?? ?? 52 63 ?? ?? 54 64 ?? ?? 44 05 04 02 b0 53 d4 33 00 01 59 63 ?? ?? 70 40 ?? ?? 26 43 54 62 ?? ?? 52 63 ?? ?? 44 03 02 03 52 64 ?? ?? 44 04 02 04 b0 43 d4 33 00 01 44 02 02 03 48 03 07 01 b7 32 8d 22 d8 03 01 01 4f 02 00 01 01 31}  //weight: 5, accuracy: Low
        $x_1_2 = "logsSniffer" ascii //weight: 1
        $x_1_3 = "enableKeyLogger" ascii //weight: 1
        $x_1_4 = "configSaveSMS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_SharkBot_C_2147834962_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SharkBot.C!MTB"
        threat_id = "2147834962"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SharkBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "logsSniffer" ascii //weight: 1
        $x_1_2 = "logsGrabber" ascii //weight: 1
        $x_1_3 = "enableKeyLogger" ascii //weight: 1
        $x_1_4 = "configSaveSMS" ascii //weight: 1
        $x_1_5 = {23 01 e5 1c d8 00 00 ff 3a 00 1b 00 6e 20 ?? ?? 04 00 0a 02 d8 03 00 ff df 02 ?? ?? 8e 22 50 02 01 00 3a 03 0e 00 d8 00 03 ff 6e 20 ?? ?? 34 00 0a 02 df 02 ?? ?? 8e 22 50 02 01 03 28 e6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

