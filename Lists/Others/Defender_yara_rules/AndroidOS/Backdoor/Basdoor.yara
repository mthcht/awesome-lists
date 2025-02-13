rule Backdoor_AndroidOS_Basdoor_A_2147815436_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/Basdoor.A!MTB"
        threat_id = "2147815436"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "Basdoor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/rat.php" ascii //weight: 1
        $x_1_2 = "_sendlargesms" ascii //weight: 1
        $x_1_3 = "~test.test" ascii //weight: 1
        $x_1_4 = "result=ok&action=nwmessage&androidid=" ascii //weight: 1
        $x_1_5 = "SendSingleMessage" ascii //weight: 1
        $x_1_6 = "getdevicefullinfo" ascii //weight: 1
        $x_1_7 = "hideicon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Backdoor_AndroidOS_Basdoor_B_2147815437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/Basdoor.B!MTB"
        threat_id = "2147815437"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "Basdoor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hideAppIcon" ascii //weight: 1
        $x_1_2 = "_sendlargesms" ascii //weight: 1
        $x_1_3 = "I Have Access :)" ascii //weight: 1
        $x_1_4 = "@rootDrDev:" ascii //weight: 1
        $x_1_5 = "getAllSMS" ascii //weight: 1
        $x_1_6 = "getcontacts" ascii //weight: 1
        $x_1_7 = "bomb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Backdoor_AndroidOS_Basdoor_D_2147819179_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/Basdoor.D!MTB"
        threat_id = "2147819179"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "Basdoor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/panel.php?link" ascii //weight: 1
        $x_1_2 = "action=hide_all&android_id=" ascii //weight: 1
        $x_1_3 = "action=lastsms&android_id=" ascii //weight: 1
        $x_1_4 = "action=install&android_id=" ascii //weight: 1
        $x_1_5 = "action=upload&android_id=" ascii //weight: 1
        $x_1_6 = "action=clipboard&android_id=" ascii //weight: 1
        $x_1_7 = "action=deviceinfo&android_id=" ascii //weight: 1
        $x_1_8 = "hideAppIcon" ascii //weight: 1
        $x_1_9 = "all-sms.txt" ascii //weight: 1
        $x_1_10 = "Call_Log.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule Backdoor_AndroidOS_Basdoor_C_2147840514_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/Basdoor.C!MTB"
        threat_id = "2147840514"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "Basdoor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "result=ok&action=nwmessage&androidid=" ascii //weight: 1
        $x_1_2 = "result=ok&action=ping&androidid=" ascii //weight: 1
        $x_1_3 = "~test.test" ascii //weight: 1
        $x_1_4 = "SendSingleMessage" ascii //weight: 1
        $x_1_5 = "hideicon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_AndroidOS_Basdoor_E_2147906017_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/Basdoor.E!MTB"
        threat_id = "2147906017"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "Basdoor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "url.php?app=10" ascii //weight: 1
        $x_1_2 = "_getewayurl" ascii //weight: 1
        $x_1_3 = "PhoneSms" ascii //weight: 1
        $x_1_4 = "com.lyufo.play" ascii //weight: 1
        $x_1_5 = "_messagesent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_AndroidOS_Basdoor_F_2147932470_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/Basdoor.F!MTB"
        threat_id = "2147932470"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "Basdoor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 10 33 76 01 00 0a 02 38 02 39 00 72 10 34 76 01 00 0c 02 1f 02 b3 14 38 02 f4 ff 54 73 00 00 22 04 b5 14 70 10 98 73 04 00 54 75 00 00 71 10 09 00 05 00 0c 05 6e 20 a4 73 54 00 6e 20 a4 73 04 00 6e 20 a4 73 24 00 6e 10 b6 73 04 00 0c 04 71 20 0a 00 43 00 54 73 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {6e 20 a4 73 08 00 71 10 ce 75 07 00 0c 07 6e 20 a4 73 78 00 1a 07 4b 06 6e 20 a4 73 78 00 6e 10 b6 73 08 00 0c 07 70 20 a7 72 76 00 27 06 72 10 c1 76 00 00 0a 02 3d 02 07 00 21 73 b1 23 23 33 ae 1b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

