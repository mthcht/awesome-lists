rule MonitoringTool_AndroidOS_MonitorMinor_A_305597_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/MonitorMinor.A!MTB"
        threat_id = "305597"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "MonitorMinor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AutoSMSRecevier" ascii //weight: 1
        $x_1_2 = "ACTION_SEND_SMS_ROUND" ascii //weight: 1
        $x_1_3 = "start send the auto sms" ascii //weight: 1
        $x_1_4 = "this round has send sms count" ascii //weight: 1
        $x_1_5 = "FakeLanucherActivity" ascii //weight: 1
        $x_1_6 = "receive a new call for" ascii //weight: 1
        $x_1_7 = "mmsc.monternet.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_MonitorMinor_B_348561_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/MonitorMinor.B!MTB"
        threat_id = "348561"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "MonitorMinor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f0 b5 03 af 4d f8 04 8d 11 46 1c 46 05 46 ff f7 ?? ff 28 68 21 46 d0 f8 ac 22 28 46 90 47 80 46 28 68 21 46 00 22 d0 f8 78 33 28 46 98 47 06 46 42 46 31 46 ff f7 ?? ff 28 68 21 46 32 46 00 23 d0 f8 7c c3 28 46 e0 47 00 20 5d f8 04 8b f0 bd}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_MonitorMinor_BA_348562_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/MonitorMinor.BA!MTB"
        threat_id = "348562"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "MonitorMinor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "_encryptita;jlkfdsa;fdlkj" ascii //weight: 1
        $x_1_2 = {0c 06 22 07 ?? ?? 70 10 ?? ?? 07 00 6e 20 ?? ?? 47 00 0c 07 1a 08 ?? ?? 6e 20 ?? ?? 87 00 0c 07 6e 10 ?? ?? 07 00 0c 07 70 30 ?? ?? 65 07 6e 10 ?? ?? 05 00 0a 06 38 06 0c 00 6e 10 ?? ?? 05 00 0b 06 16 08 00 00 31 06 06 08}  //weight: 1, accuracy: Low
        $x_1_3 = {0c 06 6e 20 ?? ?? 46 00 0c 06 22 07 ?? ?? 70 10 ?? ?? 07 00 6e 20 ?? ?? 47 00 0c 04 1a 07 ?? ?? 6e 20 ?? ?? 74 00 0c 04 6e 10 ?? ?? 04 00 0c 04 71 30 ?? ?? 56 04 6e 10 ?? ?? 05 00 0c 04 71 10 ?? ?? 04 00 12 14 6a 04 ?? ?? 71 20 ?? ?? ba 00 0c 00 11 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_MonitorMinor_BB_348563_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/MonitorMinor.BB!MTB"
        threat_id = "348563"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "MonitorMinor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {21 30 35 02 1b 00 48 00 03 02 21 45 94 05 02 05 48 05 04 05 b1 50 13 05 80 ff 35 50 08 00 d9 00 00 80 d9 00 00 7f d8 00 00 01 8d 00 4f 00 03 02 d8 00 02 01 01 02 28 e5}  //weight: 1, accuracy: High
        $x_1_2 = {21 31 35 10 1a 00 48 01 03 00 21 24 94 04 00 04 48 04 02 04 b1 41 13 04 80 ff 35 41 08 00 d9 01 01 80 d9 01 01 7f d8 01 01 01 8d 11 4f 01 03 00 d8 00 00 01 28 e6}  //weight: 1, accuracy: High
        $x_1_3 = "dalvik.system.DexClassLoader" ascii //weight: 1
        $x_1_4 = "loadClass" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

