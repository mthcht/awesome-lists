rule TrojanSpy_AndroidOS_Vultur_A_2147797028_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Vultur.A"
        threat_id = "2147797028"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Vultur"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "WebViewService::doWork" ascii //weight: 4
        $x_4_2 = "config:dialog:timeout" ascii //weight: 4
        $x_4_3 = "ScreenLock::capture" ascii //weight: 4
        $x_4_4 = "ScreenRecordService::onStartCommand" ascii //weight: 4
        $x_4_5 = "/B7AVnc;" ascii //weight: 4
        $x_1_6 = "isCapture=" ascii //weight: 1
        $x_1_7 = "record_screen" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_Vultur_JK_2147813222_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Vultur.JK"
        threat_id = "2147813222"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Vultur"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "decryptNewFormat" ascii //weight: 1
        $x_1_2 = "ensureOtpParametersIsMutable" ascii //weight: 1
        $x_1_3 = "com.privacy.account.safetyapp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Vultur_B_2147833190_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Vultur.B!MTB"
        threat_id = "2147833190"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Vultur"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ScreenRecordService" ascii //weight: 1
        $x_1_2 = "MediaUploadWorker" ascii //weight: 1
        $x_1_3 = "nstart_vnc" ascii //weight: 1
        $x_1_4 = "UnlockScreenCaptureActivity" ascii //weight: 1
        $x_1_5 = "MessagingService" ascii //weight: 1
        $x_1_6 = "NgrokDownloadWorker" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

