rule TrojanSpy_AndroidOS_Keylogger_QA_2147817404_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Keylogger.QA!MTB"
        threat_id = "2147817404"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vnc_overlay_enabled" ascii //weight: 1
        $x_1_2 = "injects_list" ascii //weight: 1
        $x_1_3 = "keylogger_enabled" ascii //weight: 1
        $x_1_4 = "last_applist_update" ascii //weight: 1
        $x_1_5 = "Enable SMS intercept" ascii //weight: 1
        $x_1_6 = "CRASH MSG TEST" ascii //weight: 1
        $x_1_7 = "hideIcon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule TrojanSpy_AndroidOS_Keylogger_B_2147822917_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Keylogger.B!MTB"
        threat_id = "2147822917"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MY_PREFS_Clicks_Count_KEY" ascii //weight: 1
        $x_1_2 = "getSYSInfo" ascii //weight: 1
        $x_1_3 = "Send1stMailTask" ascii //weight: 1
        $x_1_4 = "InGService" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Keylogger_D_2147838332_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Keylogger.D!MTB"
        threat_id = "2147838332"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "JoKeR_SeRvEr" ascii //weight: 1
        $x_1_2 = "/test/joker2" ascii //weight: 1
        $x_1_3 = "phonemonitor" ascii //weight: 1
        $x_1_4 = "CM_SENDSMS" ascii //weight: 1
        $x_1_5 = "delete-joker" ascii //weight: 1
        $x_1_6 = "HandleCalling" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_AndroidOS_Keylogger_E_2147842303_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Keylogger.E!MTB"
        threat_id = "2147842303"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Lcom/example/whatsupp" ascii //weight: 5
        $x_1_2 = "MyDifficultPassw" ascii //weight: 1
        $x_1_3 = "tcp.ngrok.io" ascii //weight: 1
        $x_1_4 = "reverse_tcp" ascii //weight: 1
        $x_1_5 = "fix.dat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_Keylogger_F_2147851300_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Keylogger.F!MTB"
        threat_id = "2147851300"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "log.txt" ascii //weight: 1
        $x_1_2 = "Lcom/keylogger/MainActivity" ascii //weight: 1
        $x_1_3 = "doinbackground" ascii //weight: 1
        $x_1_4 = "fix.dat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

