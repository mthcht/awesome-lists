rule Backdoor_Win32_Kbotrep_A_2147719285_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Kbotrep.A"
        threat_id = "2147719285"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Kbotrep"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "KBOT.INI" ascii //weight: 1
        $x_1_2 = "INJECTS.INI" ascii //weight: 1
        $x_1_3 = "WORM.INI" ascii //weight: 1
        $x_1_4 = "\\BC.INI" ascii //weight: 1
        $x_1_5 = "I'm a teapot" ascii //weight: 1
        $x_1_6 = "BASECONFIG......FJ" ascii //weight: 1
        $x_1_7 = "Elevation:Administrator!new:{" ascii //weight: 1
        $x_1_8 = "Uloader32" ascii //weight: 1
        $x_1_9 = "Uloader64" ascii //weight: 1
        $x_1_10 = "UpdateInjects" ascii //weight: 1
        $x_1_11 = "UpdateConfig" ascii //weight: 1
        $x_1_12 = "UpdateCore" ascii //weight: 1
        $x_1_13 = "UpdateWormConfig" ascii //weight: 1
        $x_1_14 = "UpdateBackconnectConfig" ascii //weight: 1
        $x_1_15 = "BotConfig" ascii //weight: 1
        $x_1_16 = "BotCommunity" ascii //weight: 1
        $x_1_17 = "InjectConfig" ascii //weight: 1
        $x_1_18 = "WormConfig" ascii //weight: 1
        $x_1_19 = "InfectedByID" ascii //weight: 1
        $x_1_20 = "OSInfectedCount" ascii //weight: 1
        $x_1_21 = "StillLoader" ascii //weight: 1
        $x_1_22 = "44DCF35866EB4992264E809EDD001737C65E28BB4DAB8DC7DA5CFA7F1AA05619" ascii //weight: 1
        $x_1_23 = "group_102" ascii //weight: 1
        $x_1_24 = "mensabuxus.net" ascii //weight: 1
        $x_1_25 = "ogrthuvwfdcfri5euwg.com" ascii //weight: 1
        $x_1_26 = "ogrthuvfewfdcfri5euwg.com" ascii //weight: 1
        $x_1_27 = {03 4d f0 80 39 e8 75 ?? 80 79 05 e9 75}  //weight: 1, accuracy: Low
        $x_1_28 = {e2 f0 81 ff 5b bc 4a 6a}  //weight: 1, accuracy: High
        $x_1_29 = {68 e8 a9 67 08 e8}  //weight: 1, accuracy: High
        $x_1_30 = {68 3c 92 3d 68 e8}  //weight: 1, accuracy: High
        $x_1_31 = {8a 44 0a 14 30 81 ?? ?? ?? ?? 41 83 f9 10 72 f0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

