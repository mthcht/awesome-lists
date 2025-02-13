rule TrojanSpy_AndroidOS_FakeBank_C_2147835830_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/FakeBank.C!MTB"
        threat_id = "2147835830"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "FakeBank"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "app.readcontacts" ascii //weight: 4
        $x_1_2 = "getAllSms" ascii //weight: 1
        $x_1_3 = "syncMess" ascii //weight: 1
        $x_1_4 = "get_address" ascii //weight: 1
        $x_1_5 = "get_folderName" ascii //weight: 1
        $x_1_6 = "cardNoEt" ascii //weight: 1
        $x_1_7 = "ccvEt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_FakeBank_C_2147835830_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/FakeBank.C!MTB"
        threat_id = "2147835830"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "FakeBank"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DeAdminReciver" ascii //weight: 1
        $x_1_2 = "/appHome/servlet/UploadImage" ascii //weight: 1
        $x_1_3 = "getBankShortBypack" ascii //weight: 1
        $x_1_4 = "getBanksInfo" ascii //weight: 1
        $x_1_5 = "getInstalledPacks" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_FakeBank_D_2147835831_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/FakeBank.D!MTB"
        threat_id = "2147835831"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "FakeBank"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "savepersonaldetails_stepfirst" ascii //weight: 1
        $x_1_2 = "com.app.manager.icici.service.update" ascii //weight: 1
        $x_1_3 = "getsearchtracking" ascii //weight: 1
        $x_1_4 = "/interactionlab/android-notification-log" ascii //weight: 1
        $x_1_5 = "cardNoEt" ascii //weight: 1
        $x_1_6 = "ccvEt" ascii //weight: 1
        $x_1_7 = "upda" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_FakeBank_BA_2147838010_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/FakeBank.BA!MTB"
        threat_id = "2147838010"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "FakeBank"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "60"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "12k8y2x5gt8d6s4q" ascii //weight: 5
        $x_5_2 = "q4s6d8tg5x2y8k2l" ascii //weight: 5
        $x_2_3 = "12k8y2" ascii //weight: 2
        $x_2_4 = "x5gt8" ascii //weight: 2
        $x_2_5 = "d6s4q" ascii //weight: 2
        $x_2_6 = "5x2y" ascii //weight: 2
        $x_2_7 = "8k2l" ascii //weight: 2
        $x_50_8 = {21 52 35 20 ?? ?? da 02 00 02 62 03 ?? ?? 48 04 05 00 d5 44 f0 00 e2 04 04 04 49 03 03 04 50 03 01 02 da 02 00 02 d8 02 02 01 62 03 ?? ?? 48 04 05 00 dd 04 04 0f 49 03 03 04 50 03 01 02 d8 00 00 01}  //weight: 50, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 5 of ($x_2_*))) or
            ((1 of ($x_50_*) and 1 of ($x_5_*) and 3 of ($x_2_*))) or
            ((1 of ($x_50_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_FakeBank_BB_2147838011_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/FakeBank.BB!MTB"
        threat_id = "2147838011"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "FakeBank"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "60"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "12k8y2x5gt8d6s4q" ascii //weight: 5
        $x_5_2 = "q4s6d8tg5x2y8k2l" ascii //weight: 5
        $x_2_3 = "12k8y2" ascii //weight: 2
        $x_2_4 = "x5gt8" ascii //weight: 2
        $x_2_5 = "d6s4q" ascii //weight: 2
        $x_2_6 = "5x2y" ascii //weight: 2
        $x_2_7 = "8k2l" ascii //weight: 2
        $x_50_8 = {da 02 01 02 [0-4] 62 03 [0-6] 48 04 05 01 [0-4] d5 44 f0 00 [0-4] e2 04 04 04 [0-4] 49 03 03 04 [0-4] 50 03 00 02 [0-6] da 02 01 02 [0-4] d8 02 02 01 [0-4] 62 03 [0-6] 48 04 05 01 [0-4] dd 04 04 0f [0-4] 49 03 03 04 [0-4] 50 03 00 02 [0-6] d8 01 01 01}  //weight: 50, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 5 of ($x_2_*))) or
            ((1 of ($x_50_*) and 1 of ($x_5_*) and 3 of ($x_2_*))) or
            ((1 of ($x_50_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_FakeBank_B_2147838432_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/FakeBank.B!MTB"
        threat_id = "2147838432"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "FakeBank"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "com/app/manager/axis/restapi" ascii //weight: 10
        $x_10_2 = "com/app/manager/hdfc/restapi" ascii //weight: 10
        $x_10_3 = "com/app/manager/rbl/restapi" ascii //weight: 10
        $x_1_4 = "savepersonaldetails_stepfirst" ascii //weight: 1
        $x_1_5 = "card_number" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_FakeBank_E_2147841567_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/FakeBank.E!MTB"
        threat_id = "2147841567"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "FakeBank"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "com.bnk" ascii //weight: 5
        $x_5_2 = "activity.MainActivityA" ascii //weight: 5
        $x_1_3 = ".apk" ascii //weight: 1
        $x_1_4 = "install_non_market_apps" ascii //weight: 1
        $x_1_5 = "activity/AppStart" ascii //weight: 1
        $x_1_6 = "starttracking" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_FakeBank_F_2147845460_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/FakeBank.F!MTB"
        threat_id = "2147845460"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "FakeBank"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/wish/defaultcallservice" ascii //weight: 1
        $x_1_2 = "AppInstallReceiver" ascii //weight: 1
        $x_1_3 = "removeAllViews" ascii //weight: 1
        $x_1_4 = "notificationTimeout" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

