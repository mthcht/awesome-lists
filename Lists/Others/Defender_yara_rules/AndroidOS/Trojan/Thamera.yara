rule Trojan_AndroidOS_Thamera_A_2147832204_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Thamera.A!MTB"
        threat_id = "2147832204"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Thamera"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SMS_APP_NEW_USER" ascii //weight: 1
        $x_1_2 = "pidarast.ru" ascii //weight: 1
        $x_1_3 = {2f 54 6f 6e 69 [0-6] 2f 74 6f 74 6b 61 2f 6d 61 73 74 65 72 2f 63 6f 6e 66 5f [0-4] 2e 6a 73 6f 6e}  //weight: 1, accuracy: Low
        $x_1_4 = "/smsapp" ascii //weight: 1
        $x_1_5 = "installed_apps_names" ascii //weight: 1
        $x_1_6 = "SMS_APP_SEND_SMS_STATUS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_AndroidOS_Thamera_B_2147840920_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Thamera.B!MTB"
        threat_id = "2147840920"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Thamera"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "s.6srvfcm" ascii //weight: 1
        $x_1_2 = "pidarast.ru" ascii //weight: 1
        $x_1_3 = "com.settingapp.app" ascii //weight: 1
        $x_1_4 = "/smsapp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_AndroidOS_Thamera_A_2147851720_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Thamera.A"
        threat_id = "2147851720"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Thamera"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "QWxsb3cgcGVybWlzc2lvbiB0byBjb250aW51ZQ=" ascii //weight: 1
        $x_1_2 = "WVc1a2NtOXBaQzV3Y205MmFXUmxjaTVVWld4bGNHaHZibmt1VTAxVFgxSkZRMFZKVmtWRQ" ascii //weight: 1
        $x_1_3 = "LmFjdGl2aXRpZXMuU3BsYXNoQWN0aXZpdHkuQmxhY2tUaGVtZQ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Thamera_C_2147852389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Thamera.C!MTB"
        threat_id = "2147852389"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Thamera"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cankl2k.php?key=1icyhd8bc7bfqphjemaa&user_id=" ascii //weight: 1
        $x_1_2 = "isSmsCapable" ascii //weight: 1
        $x_1_3 = "finishAndRemoveTask" ascii //weight: 1
        $x_1_4 = "Lcom/simplemobiletools/launcher/activities/HiddenIconsActivity" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Thamera_C_2147852389_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Thamera.C!MTB"
        threat_id = "2147852389"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Thamera"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "org/jackajks/ther/SmsReceiver" ascii //weight: 1
        $x_1_2 = "SMS_APP_NEW_CALL" ascii //weight: 1
        $x_1_3 = "ScheduledMessageReceiver" ascii //weight: 1
        $x_1_4 = "isSmsCapable" ascii //weight: 1
        $x_1_5 = "com.android.contacts/contacts" ascii //weight: 1
        $x_1_6 = "HeadlessSmsSendService" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_AndroidOS_Thamera_S_2147891463_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Thamera.S"
        threat_id = "2147891463"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Thamera"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LmFjdGl2aXRpZXMuU3BsYXNoQWN0aXZpdHkuT3Jhbmdl" ascii //weight: 1
        $x_1_2 = "WVc1a2NtOXBaQzV3Y205MmFXUmxjaTVVWld4bGNHaHZibmt1VTAxVFgxSkZRMFZKVmtWRQ=" ascii //weight: 1
        $x_1_3 = "Y2FsbF9udW1iZXI" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Thamera_D_2147908990_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Thamera.D!MTB"
        threat_id = "2147908990"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Thamera"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "permissionAksCounter" ascii //weight: 1
        $x_1_2 = "org.jackajks.thermish" ascii //weight: 1
        $x_1_3 = "sendNewSMS" ascii //weight: 1
        $x_1_4 = "FireBasemeoqaleheu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Thamera_WT_2147919243_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Thamera.WT"
        threat_id = "2147919243"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Thamera"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "QWxsb3cgcGVybWlzc2lvbiB0byBjb250aW51ZQ==" ascii //weight: 1
        $x_1_2 = "QVBQX05FVw==" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Thamera_E_2147935646_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Thamera.E!MTB"
        threat_id = "2147935646"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Thamera"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {1a 0a a0 13 71 20 1d 2a a9 00 1a 0a 02 1f 71 20 1d 2a a1 00 1a 0a 01 1f 71 20 1d 2a a2 00 62 0a be 09 6e 20 9d 19 9a 00 0c 0a 22 00 49 05 12 03 12 14 70 30 1d 23 30 04 62 03 c2 09 71 20 98 2e 3a 00 0c 04 6e 30 1e 23 30 04 62 03 b7 09}  //weight: 5, accuracy: High
        $x_5_2 = {c0 c1 13 03 21 00 a5 03 01 03 c2 31 18 03 f5 05 97 79 ed d9 a9 62 9d 01 01 03 13 03 1c 00 a5 03 01 03 c2 31 18 03 b3 35 8c c8 a5 d0 24 cb 9d 01 01 03 13 03 20 00 c5 31 71 20 cf 2e 21 00 0b 01 a5 04 01 03 17 06 ff ff 00 00 c0 64 71 20 cf 2e 21 00 0b 01 13 08 10 00 a5 08 01 08 17 0a 00 00 ff ff c0 a8 c5 3c c2 4c c2 8c 84 cd 71 40 c3 2e 0d 21 0b 01 a5 04 01 03 c0 64 84 4c 23 c4 6a 08 12 05}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Thamera_F_2147937882_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Thamera.F!MTB"
        threat_id = "2147937882"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Thamera"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 20 c0 29 51 00 0c 08 1f 08 47 01 6e 10 28 06 08 00 0c 09 1f 09 2d 02 52 9d d6 00 b1 7d 52 97 d7 00 b1 27 12 02 71 20 23 28 d2 00 0a 09 71 20 23 28 72 00 0a 0e 7b dd 71 20 23 28 d2 00 0a 0d 7b 77 71 20 23 28 72 00 0a 07 6e 10 31 06 08 00 0a 08 b0 98 b0 e8 b0 86 d8 05 05 01 01 72 01 d7}  //weight: 1, accuracy: High
        $x_1_2 = {12 03 6e 20 26 07 30 00 0c 01 6e 10 31 06 01 00 0a 03 6e 10 2e 06 01 00 0a 05 db 04 04 02 db 06 03 02 b1 64 db 06 05 02 b1 62 b0 43 b0 25 6e 55 79 06 41 32 0e 00 df 03 09 01 b1 3a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

