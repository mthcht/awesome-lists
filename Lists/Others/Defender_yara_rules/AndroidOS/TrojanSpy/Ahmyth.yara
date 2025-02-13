rule TrojanSpy_AndroidOS_Ahmyth_A_2147755426_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Ahmyth.A!MTB"
        threat_id = "2147755426"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Ahmyth"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ahmyth.mine.king.ahmyth" ascii //weight: 1
        $x_1_2 = "content://call_log/calls" ascii //weight: 1
        $x_1_3 = "content://sms/inbox" ascii //weight: 1
        $x_1_4 = "x0000lm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Ahmyth_B_2147763038_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Ahmyth.B!MTB"
        threat_id = "2147763038"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Ahmyth"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/WhatsApp/Media/WhatsApp Documents/" ascii //weight: 1
        $x_1_2 = "/.System/Records/" ascii //weight: 1
        $x_1_3 = "/system.apk" ascii //weight: 1
        $x_1_4 = "startRecording" ascii //weight: 1
        $x_1_5 = "smsList" ascii //weight: 1
        $x_1_6 = "/server/upload.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_AndroidOS_Ahmyth_E_2147768926_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Ahmyth.E!MTB"
        threat_id = "2147768926"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Ahmyth"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Ljoker/mine/joker/joker/" ascii //weight: 2
        $x_2_2 = "Lnic/goi/aarogyasetu/CoronaApplication" ascii //weight: 2
        $x_1_3 = "xjoker01" ascii //weight: 1
        $x_1_4 = "fn_hideicon" ascii //weight: 1
        $x_1_5 = "getCallsLogs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_Ahmyth_F_2147768990_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Ahmyth.F!MTB"
        threat_id = "2147768990"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Ahmyth"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/api/default-dialer" ascii //weight: 1
        $x_2_2 = "aHR0cDovLzEyMy4yNTMuMTEwLjI3" ascii //weight: 2
        $x_1_3 = "startRecording" ascii //weight: 1
        $x_1_4 = "smsList" ascii //weight: 1
        $x_1_5 = "wqlwbn0arswqlwbn0/kkdata.dat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_Ahmyth_H_2147810031_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Ahmyth.H!MTB"
        threat_id = "2147810031"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Ahmyth"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lcom/techexpert/signallite" ascii //weight: 1
        $x_1_2 = "3.tcp.ngrok.io" ascii //weight: 1
        $x_1_3 = "getCallLogs" ascii //weight: 1
        $x_1_4 = "getContact" ascii //weight: 1
        $x_1_5 = "startRecording" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_AndroidOS_Ahmyth_I_2147811080_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Ahmyth.I!MTB"
        threat_id = "2147811080"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Ahmyth"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Lcom/techexpert/spacemessanger/services" ascii //weight: 2
        $x_2_2 = "3.tcp.ngrok.io" ascii //weight: 2
        $x_1_3 = "contactsList" ascii //weight: 1
        $x_1_4 = "&manf=" ascii //weight: 1
        $x_1_5 = "Malformed close payload" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Ahmyth_J_2147816228_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Ahmyth.J!MTB"
        threat_id = "2147816228"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Ahmyth"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "getSMSList" ascii //weight: 1
        $x_1_2 = "startRecording" ascii //weight: 1
        $x_1_3 = "getCallsLogs" ascii //weight: 1
        $x_1_4 = "takePicture" ascii //weight: 1
        $x_1_5 = "getContacts" ascii //weight: 1
        $x_1_6 = "stopUsingGPS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Ahmyth_D_2147831523_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Ahmyth.D"
        threat_id = "2147831523"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Ahmyth"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/.System/Ct.csv/" ascii //weight: 1
        $x_1_2 = "IntroScreen_Activity" ascii //weight: 1
        $x_1_3 = "logk3y.txt" ascii //weight: 1
        $x_1_4 = "/.System/sm.csv/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanSpy_AndroidOS_Ahmyth_E_2147839110_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Ahmyth.E"
        threat_id = "2147839110"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Ahmyth"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Lahmyth/mine/king/ahmyth/ConnectionManager;" ascii //weight: 2
        $x_2_2 = "AhMyth's icon has been revealed!" ascii //weight: 2
        $x_2_3 = "x0000sm" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Ahmyth_M_2147923684_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Ahmyth.M!MTB"
        threat_id = "2147923684"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Ahmyth"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PermisScreen" ascii //weight: 1
        $x_1_2 = "FKPinScreen" ascii //weight: 1
        $x_1_3 = "AMSUnstopablle" ascii //weight: 1
        $x_1_4 = "DuckDuck.kt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Ahmyth_K_2147923686_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Ahmyth.K!MTB"
        threat_id = "2147923686"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Ahmyth"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "filemanager/search/oth/dir/MainActivity" ascii //weight: 1
        $x_1_2 = {01 40 01 71 20 ?? 07 04 00 6e 10 ?? 01 05 00 0c 01 1a 02 ?? 15 6e 20 ?? 19 12 00 0a 01 38 01 05 00 71 10 ?? 15 04 00 0e 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

