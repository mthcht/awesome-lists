rule TrojanSpy_AndroidOS_SpyAgnt_G_2147796909_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SpyAgnt.G!MTB"
        threat_id = "2147796909"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SpyAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/receiver/AutoStart;" ascii //weight: 1
        $x_1_2 = "/activities/LockMeNowActivity;" ascii //weight: 1
        $x_1_3 = "/services/HideAppIconService;" ascii //weight: 1
        $x_1_4 = "services/screen/ScreenshotService" ascii //weight: 1
        $x_1_5 = "/keylogger.txt" ascii //weight: 1
        $x_1_6 = "/scheduled_recorders.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_AndroidOS_SpyAgnt_I_2147816205_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SpyAgnt.I!MTB"
        threat_id = "2147816205"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SpyAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/api/uploads/api" ascii //weight: 1
        $x_1_2 = "uploadCallLog" ascii //weight: 1
        $x_1_3 = "uploadMessages" ascii //weight: 1
        $x_1_4 = "uploadContacts" ascii //weight: 1
        $x_1_5 = "uploadImages" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_AndroidOS_SpyAgnt_J_2147818741_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SpyAgnt.J!MTB"
        threat_id = "2147818741"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SpyAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "executeWithShell" ascii //weight: 1
        $x_1_2 = "executeCommand" ascii //weight: 1
        $x_1_3 = "kill_process" ascii //weight: 1
        $x_1_4 = "createScreenCaptureIntent" ascii //weight: 1
        $x_1_5 = "com/android/crust/qt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_AndroidOS_SpyAgnt_K_2147818742_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SpyAgnt.K!MTB"
        threat_id = "2147818742"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SpyAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "getInstalledPkgName" ascii //weight: 1
        $x_1_2 = "getApplicationMetaDataApk" ascii //weight: 1
        $x_1_3 = "startCalendar" ascii //weight: 1
        $x_1_4 = "startSMS" ascii //weight: 1
        $x_1_5 = "startUninstall" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SpyAgnt_M_2147818743_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SpyAgnt.M!MTB"
        threat_id = "2147818743"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SpyAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/api/uploads/api" ascii //weight: 1
        $x_1_2 = "api/uploads/callhis" ascii //weight: 1
        $x_1_3 = "getclipdata" ascii //weight: 1
        $x_1_4 = "api/uploads/apisms" ascii //weight: 1
        $x_1_5 = "getPhone" ascii //weight: 1
        $x_1_6 = "getlastknownlocation" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_AndroidOS_SpyAgnt_H_2147822907_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SpyAgnt.H!MTB"
        threat_id = "2147822907"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SpyAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Payloads/newShell;" ascii //weight: 1
        $x_1_2 = "Payloads/readCallLogs;" ascii //weight: 1
        $x_1_3 = "startFore" ascii //weight: 1
        $x_1_4 = "takescreenshot" ascii //weight: 1
        $x_1_5 = "getClipData" ascii //weight: 1
        $x_1_6 = "readSMSBox" ascii //weight: 1
        $x_1_7 = "sendData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule TrojanSpy_AndroidOS_SpyAgnt_N_2147940854_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SpyAgnt.N!MTB"
        threat_id = "2147940854"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SpyAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "psyberia/alpinequest/full/tele/TelegramService" ascii //weight: 1
        $x_1_2 = "tps://detect-infohelp.com/parse/" ascii //weight: 1
        $x_1_3 = "getTeleBotUrl" ascii //weight: 1
        $x_1_4 = "sendDataToSrv" ascii //weight: 1
        $x_1_5 = "pingTele" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

