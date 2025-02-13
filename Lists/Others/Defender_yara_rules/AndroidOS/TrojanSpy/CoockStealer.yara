rule TrojanSpy_AndroidOS_CoockStealer_A_2147834047_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/CoockStealer.A!MTB"
        threat_id = "2147834047"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "CoockStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "sendCookiesToTelegram" ascii //weight: 1
        $x_1_2 = {07 a1 07 b2 71 ?? ?? 00 00 00 0c 07 07 28 6e 20 ?? ?? 87 00 0c 07 07 74 07 47 1a 08 ?? ?? 6e 20 ?? ?? 87 00 0a 07 38 07 15 00 07 07 54 77 ?? ?? 07 48 71 20 ?? ?? 87 00 0c 07 07 75 07 57 38 07 09 00 07 07 54 77 ?? ?? 07 58}  //weight: 1, accuracy: Low
        $x_1_3 = {07 9c 1a 0d ?? ?? 07 8e 12 1f 46 0e 0e 0f 6e 10 ?? ?? 0e 00 0c 0e 6e 30 ?? ?? dc 0e 0c 0c 07 9c 1a 0d ?? ?? 6e 20 ?? ?? dc 00 0c 0c 1a 0d ?? ?? 6e 20 ?? ?? dc 00 0a 0c 38 0c 39 00 07 9c 1a 0d ?? ?? 6e 20 ?? ?? dc 00 0c 0c 07 0d 54 dd ?? ?? 1a 0e ?? ?? 1a 0f ?? ?? 72 30 ?? ?? ed 0f 0c 0d 6e 20 ?? ?? dc 00 0a 0c 38 0c 07 00 12 0c 1f 0c ?? ?? 07 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

