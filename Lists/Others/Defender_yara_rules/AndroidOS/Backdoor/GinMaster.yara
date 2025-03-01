rule Backdoor_AndroidOS_GinMaster_B_2147830156_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/GinMaster.B!MTB"
        threat_id = "2147830156"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "GinMaster"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/gamesns/GamesnsApplication" ascii //weight: 1
        $x_1_2 = "GamesnsService" ascii //weight: 1
        $x_1_3 = "GamesnsRequestParams" ascii //weight: 1
        $x_1_4 = "gamesnsLOG" ascii //weight: 1
        $x_1_5 = "webFeedViewParams" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_AndroidOS_GinMaster_C_2147833329_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/GinMaster.C!MTB"
        threat_id = "2147833329"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "GinMaster"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {21 12 35 20 0c 00 48 02 01 00 df 02 02 18 8d 22 4f 02 01 00 d8 00 00 01 28 f4}  //weight: 3, accuracy: High
        $x_1_2 = "com.gamesns" ascii //weight: 1
        $x_1_3 = "GloftSETT" ascii //weight: 1
        $x_1_4 = "mpSendGetPlayerData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_AndroidOS_GinMaster_D_2147843792_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/GinMaster.D!MTB"
        threat_id = "2147843792"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "GinMaster"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lcom/woweiqu/jrx/controller" ascii //weight: 1
        $x_1_2 = "Lcom/sostation/library/sdk" ascii //weight: 1
        $x_1_3 = "closeWebViewSplash" ascii //weight: 1
        $x_1_4 = "createAudioDirWithAppPackageName" ascii //weight: 1
        $x_1_5 = "getLastKnownLocation" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_AndroidOS_GinMaster_I_2147922770_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/GinMaster.I!MTB"
        threat_id = "2147922770"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "GinMaster"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "greenlog.bb" ascii //weight: 1
        $x_1_2 = "rate_ok" ascii //weight: 1
        $x_1_3 = "FAKE_DOMAIN_HASH" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

