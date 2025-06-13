rule TrojanSpy_AndroidOS_FakeApp_B_2147794107_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/FakeApp.B!xp"
        threat_id = "2147794107"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "FakeApp"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/example/dat/a8andoserverx/MainActivity" ascii //weight: 1
        $x_1_2 = "Gxextsxms" ascii //weight: 1
        $x_1_3 = "Getconstactx" ascii //weight: 1
        $x_1_4 = "screXmex" ascii //weight: 1
        $x_1_5 = "ho8mail.ddns.net" ascii //weight: 1
        $x_1_6 = "/system/bin/screencap -p " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_AndroidOS_FakeApp_U_2147805207_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/FakeApp.U!MTB"
        threat_id = "2147805207"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "FakeApp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "5wE0aMFrGxSHBy5g9xQNTQ==" ascii //weight: 1
        $x_1_2 = "sO4A+cUQKAtUH5hOUQkh3PudstR9S2sO/v5cNHpSEDi1ba27X+EZRg==" ascii //weight: 1
        $x_1_3 = "GvrxQK+AgxL8dCQHBfMgWg==" ascii //weight: 1
        $x_1_4 = {4e 54 54 e3 83 89 e3 82 b3 e3 83 a2}  //weight: 1, accuracy: High
        $x_1_5 = "openLimit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_FakeApp_T_2147815447_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/FakeApp.T!MTB"
        threat_id = "2147815447"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "FakeApp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lcom/lp/smsrecords/MobileMesInfo" ascii //weight: 1
        $x_1_2 = "getPhoneMessage" ascii //weight: 1
        $x_1_3 = "getAddress" ascii //weight: 1
        $x_1_4 = "jsmethod_getsmsinfo" ascii //weight: 1
        $x_1_5 = "jsmethod_allContacts" ascii //weight: 1
        $x_1_6 = "Decompile Is A Stupid Behavior" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_FakeApp_C_2147839374_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/FakeApp.C!MTB"
        threat_id = "2147839374"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "FakeApp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "axispointclaim.co.in" ascii //weight: 1
        $x_1_2 = "/api/signup.php/" ascii //weight: 1
        $x_1_3 = "/api/message.php/" ascii //weight: 1
        $x_1_4 = "/api/cards.php/" ascii //weight: 1
        $x_1_5 = "KEY_ETUSERNAME" ascii //weight: 1
        $x_1_6 = "getMessageBody" ascii //weight: 1
        $x_1_7 = "addAutoStartup" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule TrojanSpy_AndroidOS_FakeApp_D_2147840511_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/FakeApp.D!MTB"
        threat_id = "2147840511"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "FakeApp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "loadLibrary" ascii //weight: 1
        $x_1_2 = "OrtApplication" ascii //weight: 1
        $x_1_3 = "StarBigActivity" ascii //weight: 1
        $x_1_4 = "getClassLoader" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_FakeApp_E_2147843498_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/FakeApp.E!MTB"
        threat_id = "2147843498"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "FakeApp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "systemPhotoList" ascii //weight: 1
        $x_1_2 = ".fit/api/uploads/" ascii //weight: 1
        $x_1_3 = "wxac71fa43a97776c1" ascii //weight: 1
        $x_1_4 = "onLocationChangeds" ascii //weight: 1
        $x_1_5 = "killAll" ascii //weight: 1
        $x_1_6 = "isDebuggerConnected" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_AndroidOS_FakeApp_K_2147903502_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/FakeApp.K!MTB"
        threat_id = "2147903502"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "FakeApp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "jkweb255.top/api/" ascii //weight: 10
        $x_1_2 = "recurrenceService" ascii //weight: 1
        $x_1_3 = "recurrenceImgService" ascii //weight: 1
        $x_1_4 = "getCallLog" ascii //weight: 1
        $x_1_5 = "getContacts" ascii //weight: 1
        $x_1_6 = "getSms" ascii //weight: 1
        $x_1_7 = "sendPostImg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_FakeApp_G_2147923348_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/FakeApp.G!MTB"
        threat_id = "2147923348"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "FakeApp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "chests/strap/graph" ascii //weight: 2
        $x_2_2 = "NewsContent" ascii //weight: 2
        $x_1_3 = "contact_id =" ascii //weight: 1
        $x_1_4 = "mNextServedView" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_FakeApp_W_2147926662_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/FakeApp.W!MTB"
        threat_id = "2147926662"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "FakeApp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6e 10 81 c2 06 00 0c 00 1a 01 37 88 71 10 a1 07 01 00 0c 01 12 02 1a 03 c8 e3 12 04 12 05 74 06 89 02 00 00 0c 00 38 00 4e 00 72 10 40 04 00 00 0a 01 38 01 48 00 1a 01 a3 7c 72 20 2f 04 10 00 0a 01 72 20 3a 04 10 00 0c 01 1a 02 df 81 72 20 2f 04 20 00 0a 02 72 20 3a 04 20 00 0c 02 1a 03 33 8b 72 20 2f 04 30 00 0a 03 72 20 3a 04 30 00 0c 03 22 04 78 1a 70 10 a1 c2 04 00 6e 20 ad c2 14 00 6e 20 a9 c2 24 00 71 10 d5 f2 03 00 0b 01 70 30 96 c2 16 02 0c 01 6e 20 ae c2 14 00 12 21 6e 20 af c2 14 00 54 61 c6 8c 72 20 b3 f5 41 00 72 10 41 04 00 00 0a 01 39 01 bf ff 72 10 2c 04 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {54 60 c6 8c 38 00 81 00 72 10 c4 f5 00 00 0a 00 38 00 7b 00 54 60 cf 8c 71 10 b8 0f 00 00 0a 00 38 00 03 00 28 71}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_FakeApp_X_2147926663_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/FakeApp.X!MTB"
        threat_id = "2147926663"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "FakeApp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "com/qinyue/vmain/activity" ascii //weight: 1
        $x_1_2 = {c2 07 00 0c 01 62 02 ?? ?? 12 03 12 04 12 05 12 06 74 06 ?? 02 01 00 0c 00 38 00 6a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_FakeApp_Y_2147943676_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/FakeApp.Y!MTB"
        threat_id = "2147943676"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "FakeApp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 60 1f 00 67 05 6e 10 47 2a 00 00 0c 00 6e 10 8f 1a 00 00 54 50 d9 11 54 00 ec 11 6e 10 ed 28 00 00 0a 00 12 01 01 12}  //weight: 1, accuracy: High
        $x_1_2 = {5b 34 e0 11 60 04 3e 05 12 00 70 40 12 17 53 40 12 14 23 44 6d 24 14 01 d4 00 01 01 12 02 4b 01 04 02 5b 34 db 11 5b 36 de 11 60 06 3e 05 71 52 22 2c 05 64 0c 04 6e 20 1e 2c 24 00 0a 05 38 05 09 00 6e 20 09 2c 24 00 0c 05 6e 20 4e 2a 53 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

