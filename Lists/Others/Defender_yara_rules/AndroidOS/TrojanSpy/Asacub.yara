rule TrojanSpy_AndroidOS_Asacub_B_2147771274_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Asacub.B!MTB"
        threat_id = "2147771274"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Asacub"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "isAdminActive" ascii //weight: 1
        $x_1_2 = "getInstalledApplications" ascii //weight: 1
        $x_1_3 = {0a 00 d8 03 01 ff df 00 ?? ?? 8e 00 50 00 02 01 3a 03 ?? ?? d8 00 03 ff}  //weight: 1, accuracy: Low
        $x_1_4 = {0a 01 df 01 ?? ?? 8e 11 50 01 02 03 01 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Asacub_B_2147772772_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Asacub.B!dha"
        threat_id = "2147772772"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Asacub"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "developer-app.xyz" ascii //weight: 2
        $x_1_2 = "dl/test.bin" ascii //weight: 1
        $x_1_3 = "commands_data" ascii //weight: 1
        $x_1_4 = "calls_recorder" ascii //weight: 1
        $x_1_5 = "calls_log_incoming" ascii //weight: 1
        $x_1_6 = "browser_history" ascii //weight: 1
        $x_1_7 = "content://browser/searches" ascii //weight: 1
        $x_1_8 = "request_without_response" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_Asacub_A_2147817364_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Asacub.A!MTB"
        threat_id = "2147817364"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Asacub"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 c6 d0 80 fe 0a 83 d7 00 8a 74 08 02 41 84 f6 [0-5] 89 46 10 89 e3 83 c7 0f 83 e7 f0 29 fb 89 5e 04 89 dc 85 c9 [0-5] 31 ff 31 db [0-5] 90 8b 46 10 0f b6 54 38 01 47 88 d6 80 c6 d0 80 fe 09 [0-5] 89 d0 89 da 8b 5e 04 88 04 13 89 d3 43 39 cf}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Asacub_C_2147822184_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Asacub.C!MTB"
        threat_id = "2147822184"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Asacub"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f 70 72 69 76 61 74 65 2f [0-16] 2e 70 68 70}  //weight: 1, accuracy: Low
        $x_1_2 = "trafDeCr" ascii //weight: 1
        $x_1_3 = "SmsActivity" ascii //weight: 1
        $x_1_4 = "goR00t" ascii //weight: 1
        $x_1_5 = "Go_P00t_request" ascii //weight: 1
        $x_1_6 = "state1letsgotxt" ascii //weight: 1
        $x_1_7 = "185.198.57.24" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule TrojanSpy_AndroidOS_Asacub_C_2147822184_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Asacub.C!MTB"
        threat_id = "2147822184"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Asacub"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {21 84 35 40 35 00 d8 02 02 01 d5 22 ff 00 54 74 ?? 00 48 04 04 02 b0 41 d5 11 ff 00 54 74 ?? 00 48 04 04 01 54 75 ?? 00 54 76 ?? 00 48 06 06 02 4f 06 05 01 54 75 ?? 00 4f 04 05 02 54 74 ?? 00 48 04 04 02 54 75 ?? 00 48 05 05 01 b0 54 d5 44 ff 00 54 75 ?? 00 48 04 05 04 48 05 08 00 b7 54 8d 44 4f 04 03 00 d8 00 00 01 28 cb}  //weight: 5, accuracy: Low
        $x_5_2 = {35 60 41 00 ?? ?? ?? ?? 54 72 ?? 00 ?? ?? ?? ?? 48 02 02 00 ?? ?? ?? ?? b0 21 ?? ?? ?? ?? 48 02 03 ?? ?? ?? ?? 00 b0 21 ?? ?? ?? ?? d5 11 ff ?? ?? ?? ?? 00 54 72 ?? ?? ?? ?? ?? 00 48 02 02 01 ?? ?? ?? ?? 54 74 ?? ?? ?? ?? ?? 00 54 75 ?? ?? ?? ?? ?? 00 48 05 05 ?? ?? ?? ?? 00 4f 05 04 01 ?? ?? ?? ?? 54 74 ?? ?? ?? ?? ?? 00 4f 02 04 ?? ?? ?? ?? 00 d8 00 00 01 ?? ?? ?? ?? 28 c1}  //weight: 5, accuracy: Low
        $x_1_3 = "hellowopung.com/dle40z19ii6p/index.php" ascii //weight: 1
        $x_1_4 = "gonoprome.com/fv5sc5g9oz2dl04u/index.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_Asacub_F_2147834580_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Asacub.F!MTB"
        threat_id = "2147834580"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Asacub"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/AlarmReceiverSmsMan" ascii //weight: 2
        $x_2_2 = "/HeadlessSmsSendService" ascii //weight: 2
        $x_1_3 = "/AlarmReceiverKnock" ascii //weight: 1
        $x_1_4 = "/ActivityCard" ascii //weight: 1
        $x_1_5 = "/SrvProcMon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_Asacub_D_2147834958_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Asacub.D!MTB"
        threat_id = "2147834958"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Asacub"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "42"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "DeviceAdminSample" ascii //weight: 10
        $x_10_2 = "ActivityGetCC" ascii //weight: 10
        $x_10_3 = "SMSMonitor" ascii //weight: 10
        $x_10_4 = "TukTuk" ascii //weight: 10
        $x_10_5 = "/ssl_tmp/" ascii //weight: 10
        $x_1_6 = "block_phone" ascii //weight: 1
        $x_1_7 = "get_history" ascii //weight: 1
        $x_1_8 = "get_contacts" ascii //weight: 1
        $x_1_9 = "get_listapp" ascii //weight: 1
        $x_1_10 = "send_ussd" ascii //weight: 1
        $x_1_11 = "get_cc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 2 of ($x_1_*))) or
            ((5 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_Asacub_G_2147839370_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Asacub.G!MTB"
        threat_id = "2147839370"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Asacub"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "33"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "Lcom/adobe/sslpath/ActivityBlank" ascii //weight: 10
        $x_10_2 = "/ssl_tmp/" ascii //weight: 10
        $x_10_3 = {64 61 69 6d 6f 69 64 6f 6d 61 69 6e 65 6d 6e 65 2e 69 6e 66 6f 2f [0-48] 2f 69 6e 64 65 78 2e 70 68 70}  //weight: 10, accuracy: Low
        $x_1_4 = "GPS_track_current" ascii //weight: 1
        $x_1_5 = "get_listapp" ascii //weight: 1
        $x_1_6 = "get_allsms" ascii //weight: 1
        $x_1_7 = "get_history" ascii //weight: 1
        $x_1_8 = "get_contacts" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

