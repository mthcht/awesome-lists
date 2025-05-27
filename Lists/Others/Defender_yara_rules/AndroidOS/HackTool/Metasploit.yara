rule HackTool_AndroidOS_Metasploit_A_2147782822_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:AndroidOS/Metasploit.A"
        threat_id = "2147782822"
        type = "HackTool"
        platform = "AndroidOS: Android operating system"
        family = "Metasploit"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/metasploit/Screen1.yail" ascii //weight: 1
        $x_1_2 = "Anonymous/ms.sh" ascii //weight: 1
        $x_1_3 = "/joker.sh" ascii //weight: 1
        $x_1_4 = "/package.apk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule HackTool_AndroidOS_Metasploit_D_2147794289_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:AndroidOS/Metasploit.D!MTB"
        threat_id = "2147794289"
        type = "HackTool"
        platform = "AndroidOS: Android operating system"
        family = "Metasploit"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/metasploit.dat" ascii //weight: 1
        $x_1_2 = "metasploit/PayloadTrustManager.class" ascii //weight: 1
        $x_1_3 = "Lcom/metasploit/meterpreter/AndroidMeterpreter" ascii //weight: 1
        $x_1_4 = "Lmetasploit/JMXPayload" ascii //weight: 1
        $x_1_5 = "AndroidMeterpreter" ascii //weight: 1
        $x_1_6 = "android_dump_calllog" ascii //weight: 1
        $x_1_7 = "android_dump_contacts" ascii //weight: 1
        $x_1_8 = "clipboard_monitor_dump" ascii //weight: 1
        $x_1_9 = "stdapi_webcam_audio_record_android" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_AndroidOS_Metasploit_C_2147930220_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:AndroidOS/Metasploit.C!MTB"
        threat_id = "2147930220"
        type = "HackTool"
        platform = "AndroidOS: Android operating system"
        family = "Metasploit"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 30 00 01 38 00 13 00 07 30 1f 00 00 01 12 01 72 10 ec 1d 03 00 0a 03 1c 02 0e 01 72 40 40 04 10 23 0c 03 1f 03 b4 09 11 03 12 03 11 03 00 00 03 00}  //weight: 1, accuracy: High
        $x_1_2 = {54 20 0c 00 6e 10 09 07 00 00 0c 00 6e 20 78 03 30 00 0c 00 39 00 10 00 22 00 c4 06 70 10 53 1f 00 00 54 21 0c 00 6e 10 09 07 01 00 0c 01 6e 30 88 03 31 00 11 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_AndroidOS_Metasploit_E_2147935635_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:AndroidOS/Metasploit.E!MTB"
        threat_id = "2147935635"
        type = "HackTool"
        platform = "AndroidOS: Android operating system"
        family = "Metasploit"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {1a 00 08 0e 71 10 c0 21 00 00 0c 00 1a 01 b7 0f 12 02 23 22 61 06 6e 30 ca 21 10 02 0c 01 12 00 12 02 6e 30 7c 22 01 02 0c 00 1f 00 18 00 39 00 14 00 22 00 6f 00 71 00 7c 01 00 00 0c 02 70 20 6b 01 20 00 22 02 cb 01 70 20 e5 0a 12 00 6e 20 71 01 20 00 0e 00}  //weight: 1, accuracy: High
        $x_1_2 = {b7 21 59 01 44 05 54 30 28 04 54 31 28 04 52 11 44 05 54 32 28 04 52 22 7d 05 b7 21 59 01 7d 05 54 30 28 04 54 31 28 04 52 11 be 05 54 32 28 04 52 22 7d 05 b6 21 59 01 7d 05 54 30 28 04 54 31 28 04 52 11 12 05 54 32 28 04 52 22 62 05 b6 21 59 01 62 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_AndroidOS_Metasploit_F_2147942301_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:AndroidOS/Metasploit.F!MTB"
        threat_id = "2147942301"
        type = "HackTool"
        platform = "AndroidOS: Android operating system"
        family = "Metasploit"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {1a 01 09 01 12 02 23 22 7e 00 6e 30 ae 00 10 02 0c 01 12 00 12 02 6e 30 ce 00 01 02 0c 00 1f 00 0e 00 39 00 14 00 22 00 1e 00 71 00 30 00 00 00 0c 02 70 20 2e 00 20 00 22 02 3f 00 70 20 8b 00 12 00 6e 20 2f 00 20 00}  //weight: 1, accuracy: High
        $x_1_2 = {1a 01 58 00 62 02 09 00 71 10 c2 00 02 00 0c 02 71 10 c2 00 02 00 0c 03 6e 10 bc 00 03 00 0a 03 d8 03 03 11 22 04 5f 00 70 20 c4 00 34 00 1a 03 b5 00 6e 20 c7 00 34 00 0c 03 6e 20 c7 00 23 00 0c 02 6e 10 c8 00 02 00 0c 02 71 20 39 00 21 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

