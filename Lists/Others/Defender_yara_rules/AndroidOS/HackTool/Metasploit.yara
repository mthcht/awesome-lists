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

