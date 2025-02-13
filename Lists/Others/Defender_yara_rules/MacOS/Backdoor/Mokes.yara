rule Backdoor_MacOS_Mokes_2147741433_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/Mokes"
        threat_id = "2147741433"
        type = "Backdoor"
        platform = "MacOS: "
        family = "Mokes"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sub_I_bot_main_macx_clang_release_plugin_import.cpp" ascii //weight: 1
        $x_1_2 = "sub_I_qrc_resource_bot.cpp" ascii //weight: 1
        $x_1_3 = "sub_I_avfcamerasession.mm" ascii //weight: 1
        $x_1_4 = "sub_I_qmediametadata.cpp" ascii //weight: 1
        $x_1_5 = "sub_I_qaudiobuffer.cpp" ascii //weight: 1
        $x_1_6 = "sub_I_qaudiodeviceinfo.cpp" ascii //weight: 1
        $x_1_7 = "/ccXXXXXX" ascii //weight: 1
        $x_1_8 = "jikenick12and67.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Backdoor_MacOS_Mokes_A_2147741434_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/Mokes.A"
        threat_id = "2147741434"
        type = "Backdoor"
        platform = "MacOS: "
        family = "Mokes"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "avfoundationcamera" ascii //weight: 1
        $x_1_2 = {52 49 46 46 00 73 63 72 65 65 6e 73 68 6f 74 73 2f}  //weight: 1, accuracy: High
        $x_1_3 = {2a 2e 64 6f 63 00 2a 2e 64 6f 63 78 00 2a 2e 78 6c 73 00 2a 2e 78 6c 73 78 00 51 41 75 64 69 6f}  //weight: 1, accuracy: High
        $x_1_4 = {53 70 6f 74 6c 69 67 68 74 64 00 53 6b 79 70 65 00 73 6f 61 67 65 6e 74 00 44 72 6f 70 62 6f 78}  //weight: 1, accuracy: High
        $x_1_5 = {71 75 69 63 6b 6c 6f 6f 6b 64 00 47 6f 6f 67 6c 65 00 43 68 72 6f 6d 65}  //weight: 1, accuracy: High
        $x_1_6 = {46 69 72 65 66 6f 78 00 50 72 6f 66 69 6c 65 73}  //weight: 1, accuracy: High
        $x_1_7 = {74 72 75 73 74 64 00 6b 6b 74 00 2f 63 63 58 58 58 58 58 58}  //weight: 1, accuracy: High
        $x_1_8 = "powershell.exe" wide //weight: 1
        $x_1_9 = "/keys/bot" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MacOS_Mokes_B_2147756467_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/Mokes.B!MTB"
        threat_id = "2147756467"
        type = "Backdoor"
        platform = "MacOS: "
        family = "Mokes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "storeuserd" ascii //weight: 1
        $x_1_2 = "jikenick12and67.com" ascii //weight: 1
        $x_1_3 = "/keys/bot" wide //weight: 1
        $x_1_4 = "/ccXXXXXX.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

