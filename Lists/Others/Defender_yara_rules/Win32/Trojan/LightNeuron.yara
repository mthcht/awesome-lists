rule Trojan_Win32_LightNeuron_D_2147794412_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LightNeuron.D!dha"
        threat_id = "2147794412"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LightNeuron"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Event333" ascii //weight: 1
        $x_1_2 = {56 71 56 49 a9 b9 e3 ef e0 ef}  //weight: 1, accuracy: High
        $x_2_3 = "36b1f4a-82b9-eb06-7c1e-90b4b2d5c27d" ascii //weight: 2
        $x_2_4 = {46 4c 00 53 56 00 42 4c 45}  //weight: 2, accuracy: High
        $x_2_5 = {c8 cb ca cd cc f6 c2 cc d0 f6 ce cc c7 cc db c8 dd c0 c6 c7}  //weight: 2, accuracy: High
        $x_2_6 = {12 50 30 74 12 50 31 43 0c 56 64 4a 0a 6a 42 53}  //weight: 2, accuracy: High
        $x_2_7 = {04 01 00 00 c6 [0-3] 77 c6 [0-3] 69 c6 [0-3] 6e c6 [0-3] 6d}  //weight: 2, accuracy: Low
        $x_2_8 = {b9 03 00 1f 00 c6 [0-3] 47 c6 [0-3] 6c}  //weight: 2, accuracy: Low
        $n_12_9 = "simpleValidate" ascii //weight: -12
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_LightNeuron_A_2147834554_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LightNeuron.A"
        threat_id = "2147834554"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LightNeuron"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "COMMAND_REPLY_ATTACH_NAME" ascii //weight: 1
        $x_1_2 = "COMMAND_REPLY_SUBJECT" ascii //weight: 1
        $x_1_3 = "CONFIG_FILE_NAME" ascii //weight: 1
        $x_1_4 = "CONFIG_UPDATE_INTERVAL" ascii //weight: 1
        $x_1_5 = "DEBUG_LOG_FILE_NAME" ascii //weight: 1
        $x_1_6 = "LIMITS_MAILS_PER_SECOND_REFRESH_INTERVAL" ascii //weight: 1
        $x_1_7 = "LIMITS_MEMORY_LOAD_REFRESH_INTERVAL" ascii //weight: 1
        $x_1_8 = "POSTFIX_INCOMING_PATH" ascii //weight: 1
        $x_1_9 = "SEND_AT_NIGHT" ascii //weight: 1
        $x_1_10 = "SEND_NEW_MAIL_SERVER" ascii //weight: 1
        $x_1_11 = "TMP_ID_PATH" ascii //weight: 1
        $x_1_12 = "ZIP_FILE_NAME" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

