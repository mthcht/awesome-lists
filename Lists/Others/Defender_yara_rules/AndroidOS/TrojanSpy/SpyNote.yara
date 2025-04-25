rule TrojanSpy_AndroidOS_SpyNote_2147795381_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SpyNote.g"
        threat_id = "2147795381"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SpyNote"
        severity = "Critical"
        info = "g: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {12 02 12 13 33 31 12 00 62 01 ?? ?? 38 01 0b 00 13 01 f4 01 67 01 ?? ?? 62 01 ?? ?? 71 10 ?? ?? 01 00 67 02 ?? ?? 28 28 60 01 ?? ?? 33 31 12 00 62 01 ?? ?? 38 01 0b 00 13 01 f5 01 67 01 ?? ?? 62 01 ?? ?? 71 10 ?? ?? 01 00 67 02 ?? ?? 28 14 60 01 ?? ?? 33 31 11 00 62 01 ?? ?? 38 01 0b 00 13 01 f6 01 67 01 ?? ?? 62 01 ?? ?? 71 10 ?? ?? 01 00 67 02 ?? ?? 71 10 ?? ?? 00 00 6e 20 ?? ?? 30 00 6e 10 ?? ?? 00 00 12 21 0f 01}  //weight: 3, accuracy: Low
        $x_1_2 = "onStartCommand" ascii //weight: 1
        $x_1_3 = "onLocationChanged" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_SpyNote_E_2147808787_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SpyNote.E!MTB"
        threat_id = "2147808787"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SpyNote"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {12 02 12 13 33 31 12 00 62 01 ?? ?? 38 01 0b 00 13 01 f4 01 67 01 ?? ?? 62 01 ?? ?? 71 10 ?? ?? 01 00 67 02 ?? ?? 28 28 60 01 ?? ?? 33 31 12 00 62 01 ?? ?? 38 01 0b 00 13 01 f5 01 67 01 ?? ?? 62 01 ?? ?? 71 10 ?? ?? 01 00 67 02 ?? ?? 28 14}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SpyNote_L_2147839372_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SpyNote.L!MTB"
        threat_id = "2147839372"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SpyNote"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_callr_lsnr_" ascii //weight: 1
        $x_1_2 = "iamworking" ascii //weight: 1
        $x_1_3 = "isEmulator_1" ascii //weight: 1
        $x_1_4 = "enabled_accessibility_services" ascii //weight: 1
        $x_1_5 = "is_dozemode" ascii //weight: 1
        $x_1_6 = "onIncomingCallAnswered" ascii //weight: 1
        $x_1_7 = "onOutgoingCallStarted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SpyNote_M_2147839827_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SpyNote.M!MTB"
        threat_id = "2147839827"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SpyNote"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 00 09 04 1a 06 ?? ?? 6e 20 ?? ?? 60 00 0a 00 38 00 0a 00}  //weight: 1, accuracy: Low
        $x_1_2 = {38 00 3f 00 1a 00 ?? ?? 6e 20 ?? ?? 05 00 0a 00 1a 01 ?? ?? 15 02 ?? ?? 38 00 1a 00 12 10 6a 00 ?? ?? 22 00 ?? ?? 62 03 ?? ?? 1c 04 ?? ?? 70 30 ?? ?? 30 04 6e 20 ?? ?? 20 00 6e 30 ?? ?? 10 05 62 05 ?? ?? 6e 20 ?? ?? 05 00 28 1a 12 05 6a 05 ?? ?? 22 05 ?? ?? 62 00 ?? ?? 1c 03 ?? ?? 70 30 ?? ?? 05 03 6e 20 ?? ?? 25 00 1a 00 ?? ?? 6e 30 ?? ?? 15 00 62 00 ?? ?? 6e 20 ?? ?? 50 00 0e 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SpyNote_N_2147843536_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SpyNote.N!MTB"
        threat_id = "2147843536"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SpyNote"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "enabled_accessibility_services" ascii //weight: 1
        $x_1_2 = ".costm" ascii //weight: 1
        $x_1_3 = ".MainActive" ascii //weight: 1
        $x_1_4 = "/Config/sys/apps/log/log-" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SpyNote_J_2147851238_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SpyNote.J!MTB"
        threat_id = "2147851238"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SpyNote"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ask_battary" ascii //weight: 1
        $x_1_2 = "isEmu_DIV_ID_lator" ascii //weight: 1
        $x_1_3 = "ScreenshotResult" ascii //weight: 1
        $x_1_4 = "GetRequierdPrims" ascii //weight: 1
        $x_1_5 = "getmet2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SpyNote_O_2147919055_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SpyNote.O!MTB"
        threat_id = "2147919055"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SpyNote"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/Config/sys/apps/log" ascii //weight: 1
        $x_1_2 = "_callr_lsnr_" ascii //weight: 1
        $x_1_3 = "GetRequierdPrims" ascii //weight: 1
        $x_1_4 = {22 0e c8 0e 07 e2 76 0a ee 3c 02 00 71 10 ?? 3d 0e 00 0c 0e 5b de e9 30 54 d0 d7 30 22 02 ef 04 70 30 2d 1d e2 00 71 10 ?? 3d 02 00 54 de d7 30 54 d0 d9 30 22 02 ef 04 70 40 2e 1d e2 10 71 10 ?? 3d 02 00 0c 0e 5b de ea 30}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SpyNote_P_2147933421_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SpyNote.P!MTB"
        threat_id = "2147933421"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SpyNote"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "splash.app.main.RECORD" ascii //weight: 1
        $x_1_2 = "enabled_notification_listeners" ascii //weight: 1
        $x_1_3 = "Lsplash/app/SensorRestarterBroadcastReceiver" ascii //weight: 1
        $x_1_4 = "/Config/sys/apps/log/log-" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SpyNote_Q_2147940015_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SpyNote.Q!MTB"
        threat_id = "2147940015"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SpyNote"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "invoke_spynote_payload" ascii //weight: 1
        $x_1_2 = "key_logger_Started" ascii //weight: 1
        $x_1_3 = "getPassKeyLoggerText" ascii //weight: 1
        $x_1_4 = "OfflineLoggerID" ascii //weight: 1
        $x_1_5 = "getLockPIN" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SpyNote_R_2147940018_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SpyNote.R!MTB"
        threat_id = "2147940018"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SpyNote"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {22 00 08 00 70 10 11 00 00 00 1c 01 1c 00 6e 10 43 00 01 00 0c 01 1a 02 45 00 6e 30 12 00 20 01 1a 01 0a 00 12 12 6e 30 13 00 10 02 12 21 23 11 3a 00 12 03 4d 00 01 03 4d 05 01 02 71 20 36 00 14 00 0e 00}  //weight: 1, accuracy: High
        $x_1_2 = {22 05 25 00 71 10 48 00 01 00 0c 06 6e 10 10 00 09 00 0c 07 70 30 3d 00 65 07 1a 06 00 00 23 37 3a 00 1a 08 61 00 4d 08 07 00 1a 08 66 00 4d 08 07 04 71 20 46 00 76 00 0c 06 6e 20 44 00 65 00 0c 05 1a 06 71 00 23 47 39 00 1c 08 3a 00 4d 08 07 00 6e 30 42 00 65 07 0c 05 69 05 15 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

