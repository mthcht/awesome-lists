rule TrojanSpy_AndroidOS_Bray_A_2147794306_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Bray.A"
        threat_id = "2147794306"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Bray"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "sp_device_unique_id" ascii //weight: 2
        $x_1_2 = "startSendLocal" ascii //weight: 1
        $x_1_3 = "sp_connect_url" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_Bray_A_2147797650_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Bray.A!MTB"
        threat_id = "2147797650"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Bray"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {38 03 13 00 54 23 ?? 00 1a 00 ?? 33 71 10 ?? ?? 00 00 0c 00 12 01 71 30 ?? ?? 03 01 0c 03 6e 10 ?? ?? 03 00}  //weight: 1, accuracy: Low
        $x_1_2 = {39 00 fa 02 54 80 ?? ?? 62 03 ?? ?? 33 30 f4 02 54 80 ?? ?? 52 03 ?? ?? 32 13 d0 02 32 23 04 00}  //weight: 1, accuracy: Low
        $x_1_3 = {36 31 1b 00 12 21 22 03 ?? ?? 70 10 ?? ?? 03 00 6e 30 ?? ?? 10 03 60 01 ?? ?? 13 03 12 00 34 31 0c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Bray_B_2147809493_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Bray.B!MTB"
        threat_id = "2147809493"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Bray"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FBotFwAHGQsQEDETGgs=" ascii //weight: 1
        $x_1_2 = "FBotBwcGADEXBQABDRU=" ascii //weight: 1
        $x_1_3 = "FA8cEDwEBCwKMwsEGwgJGREbSSQ+JhAHClVH" ascii //weight: 1
        $x_1_4 = "BAUcAAoHA1RcSx0LG0gDHBYAEQ==" ascii //weight: 1
        $x_1_5 = "FA8cEAwGGRoSBxo=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Bray_D_2147824117_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Bray.D!MTB"
        threat_id = "2147824117"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Bray"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {21 00 0c 02 1a 03 00 2f 6e 20 ?? ?? 23 00 0a 02 b7 c2 38 02 ?? ?? 54 02 ae 3e 6e 10 ?? ?? 02 00 0c 02 28 07}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Bray_E_2147826538_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Bray.E!MTB"
        threat_id = "2147826538"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Bray"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0c 04 6e 10 ?? ?? 04 00 0c 06 1f 06 22 02 6e 10 14 07 04 00 0a 08 32 b8 ?? ?? 55 68 74 02 38 08 [0-5] 52 68 e4 00 b1 85 6e 10 ?? ?? 04 00 0a 08 6e 10 ?? ?? 04 00 0a 09 db 0a 09 02 91 0a 02 0a 91 0c 05 08 b0 a9 6e 59 ?? ?? c4 5a 52 64 e3 00 b0 48 b0 38 b1 85 d8 07 07 01}  //weight: 1, accuracy: Low
        $x_1_2 = "getMessageBody" ascii //weight: 1
        $x_1_3 = "getInstalledPackages" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Bray_F_2147831872_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Bray.F!MTB"
        threat_id = "2147831872"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Bray"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {22 01 70 00 70 10 33 02 01 00 6e 10 2d 02 05 00 0c 02 12 00 21 23 35 30 33 00 dc 03 00 04 2b 03 35 00 00 00 49 03 02 00 df 03 03 ff 8e 33 6e 20 34 02 31 00 d8 00 00 01 28 ee 49 03 02 00 14 04 4f db 04 00 b7 43 8e 33 6e 20 34 02 31 00 28 f3 49 03 02 00 14 04 d7 de d3 59 b7 43 8e 33 6e 20 34 02 31 00 28 e8 49 03 02 00 14 04 0d 09 d6 a0 b7 43 8e 33 6e 20 34 02 31 00 28 dd 6e 10 39 02 01 00 0c 00 11 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Bray_C_2147833631_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Bray.C!MTB"
        threat_id = "2147833631"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Bray"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ERM7Gw0OFD0BCAcFBhY=" ascii //weight: 1
        $x_1_2 = "DgIKAgwEPBEIGg==" ascii //weight: 1
        $x_1_3 = "AQwKHAAPF1hKRhoPEEsBCwMMGg==" ascii //weight: 1
        $x_1_4 = "ChcQGF9OTAAEBg0XDw0bEU8XDRVGBQsQEEYNFQ4O" ascii //weight: 1
        $x_1_5 = "ERM7HRUNDAMBNhkHEQkBFhIKDQs=" ascii //weight: 1
        $x_1_6 = "MQYKDCYODRYECh0wBgcNDBcGEA==" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_AndroidOS_Bray_H_2147834393_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Bray.H!MTB"
        threat_id = "2147834393"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Bray"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {35 03 14 00 34 14 03 00 12 04 48 05 07 03 6e 20 ?? ?? 48 00 0a 06 b7 65 8d 55 4f 05 07 03 d8 03 03 01 d8 04 04 01 28 ed}  //weight: 1, accuracy: Low
        $x_1_2 = "getMessageBody" ascii //weight: 1
        $x_1_3 = "getOriginatingAddress" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Bray_H_2147834393_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Bray.H!MTB"
        threat_id = "2147834393"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Bray"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/index/api/uploadSms" ascii //weight: 1
        $x_1_2 = "/index/api/queryIsBlackList?phone=" ascii //weight: 1
        $x_1_3 = "/index/api/getSmsList?drive_id=" ascii //weight: 1
        $x_1_4 = "/index/api/initDrive" ascii //weight: 1
        $x_1_5 = "deleteCallLog" ascii //weight: 1
        $x_1_6 = "getSmsFromPhone" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

