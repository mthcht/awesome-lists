rule TrojanDropper_AndroidOS_SAgnt_S_2147808283_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/SAgnt.S!MTB"
        threat_id = "2147808283"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cp /sdcard/zihao.l /system/app/" ascii //weight: 1
        $x_1_2 = "chmod 644 /system/app/zihao.apk" ascii //weight: 1
        $x_1_3 = "checkRootPermission" ascii //weight: 1
        $x_1_4 = "rootShell" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_SAgnt_F_2147819331_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/SAgnt.F!MTB"
        threat_id = "2147819331"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {12 00 22 01 ?? ?? 71 10 ?? ?? 08 00 0c 02 70 20 ?? ?? 21 00 22 02 ?? ?? 70 10 ?? ?? 02 00 6e 10 ?? ?? 09 00 0c 03 6e 10 ?? ?? 01 00 0c 04 21 45 01 01 35 50 13 00 49 06 04 00 21 37 94 07 01 07 49 07 03 07 b7 76 8e 66 6e 20 ?? ?? 62 00 d8 01 01 01 d8 00 00 01 28 ee 6e 10 ?? ?? 02 00 0c 00 11 00}  //weight: 2, accuracy: Low
        $x_1_2 = "com.jshare5." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_SAgnt_G_2147822252_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/SAgnt.G!MTB"
        threat_id = "2147822252"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4c 24 40 8d ab ?? 03 00 00 0f b6 4c 11 01 32 4c 05 00 83 c0 01 39 44 24 1c 88 0c 17 b9 00 00 00 00 0f 44 c1 83 c2 01 39 d6 75 d4}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 84 1d 00 ?? ?? ?? 8d 8b ?? 03 00 00 89 74 24 04 32 04 39 83 c7 01 0f be c0 89 04 24 e8 ?? f6 ff ff 3b 7c 24 28 b8 00 00 00 00 0f 44 f8 83 c5 01 81 fd ?? ?? 01 00 75 c6 89 34 24 e8 ?? f6 ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_SAgnt_H_2147824876_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/SAgnt.H!MTB"
        threat_id = "2147824876"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 07 39 07 06 00 12 17 6e 20 ?? 00 76 00 22 01 ?? 00 70 10 ?? 00 01 00 23 b2 ?? 00 4d 0d 02 08 4d 0e 02 09 4d 01 02 0a 6e 30 ?? 00 36 02 0c 01 1f 01 ?? 00 6e 10 ?? 00 00 00 0c 02 6e 10 ?? 00 02 00 0c 02 21 05 21 16 b0 65 71 20 ?? 00 52 00 0c 02 1f 02 ?? 00 21 05 71 55 ?? 00 80 82 21 00 21 15 71 55 ?? 00 81 02 6e 30 ?? 00 34 02}  //weight: 1, accuracy: Low
        $x_1_2 = "com/main/stub" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_SAgnt_J_2147826413_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/SAgnt.J!MTB"
        threat_id = "2147826413"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 01 05 34 62 0a 00 12 01 08 00 11 00 6e 40 ?? ?? 40 51 01 21 28 ea dc 06 02 08 db 06 06 04 12 27 23 77 ?? ?? 12 08 e0 09 0b 10 b6 a9 4b 09 07 08 12 18 e0 09 0d 10 b6 c9 4b 09 07 08 44 06 07 06 dc 07 02 04 e0 07 07 03 b9 76 8d 66 48 07 04 03 b7 76 8d 66 8d 66 8d 66 4f 06 04 03 d8 03 03 01 d8 02 02 01 28 cd}  //weight: 1, accuracy: Low
        $x_1_2 = {0a 02 34 20 07 00 6e 10 ?? ?? 01 00 0c 00 11 00 6e 20 ?? ?? 05 00 0a 02 71 00 ?? ?? 00 00 0c 03 71 00 ?? ?? 00 00 12 04 49 03 03 04 b7 32 8e 22 6e 20 ?? ?? 21 00 d8 00 00 01 28 e0}  //weight: 1, accuracy: Low
        $x_1_3 = "getClassLoader" ascii //weight: 1
        $x_1_4 = "deleteFile" ascii //weight: 1
        $x_1_5 = "getAssets" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_SAgnt_E_2147827425_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/SAgnt.E!MTB"
        threat_id = "2147827425"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {21 13 35 32 0b 00 48 03 01 02 b7 03 8d 33 4f 03 01 02 d8 02 02 01 28 f5 22 00 ?? ?? 62 02 ?? ?? 70 30}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_SAgnt_A_2147828536_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/SAgnt.A!xp"
        threat_id = "2147828536"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RawInputFileE" ascii //weight: 1
        $x_1_2 = "checkApkItemRK7ApkItem" ascii //weight: 1
        $x_1_3 = "stringstuff11unpackArrayEiPtm" ascii //weight: 1
        $x_1_4 = "jniutils::getAppRootDir(%p, %p)" ascii //weight: 1
        $x_1_5 = "getJavaCaller(%p)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_SAgnt_K_2147829872_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/SAgnt.K!MTB"
        threat_id = "2147829872"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {35 d9 3f 00 48 0d 04 09 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0c 0e ?? ?? ?? ?? ?? ?? 0b 10 05 00 10 00 84 0f 48 0e 0e 0f b7 ed 8d dd 4f 0d 08 09 ?? ?? ?? ?? ?? ?? 0b 0e 16 10 01 00 9b 0e 0e 10 ?? ?? ?? ?? ?? ?? 0c 0a ?? ?? ?? ?? ?? ?? 0b 0e ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0c 0d 21 dd 81 d0 05 10 00 00 31 0d 0e 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_SAgnt_L_2147832628_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/SAgnt.L!MTB"
        threat_id = "2147832628"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {35 28 14 00 12 04 21 16 35 64 0d 00 48 06 01 04 48 07 03 08 b7 76 8d 66 4f 06 01 04 d8 04 04 01 28 f3 d8 08 08 01 28 ed}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_SAgnt_M_2147836736_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/SAgnt.M!MTB"
        threat_id = "2147836736"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {d1 75 11 24 48 07 03 08 d0 44 d0 1a dc 09 08 03 48 09 01 09 14 0a 99 90 00 00 93 0b 05 04 b0 ba 91 0b 04 0a b0 5b da 0b 0b 00 b0 7b 93 07 05 05 db 07 07 01 df 07 07 01 b0 7b b4 55 b0 5b 97 05 0b 09 8d 55 4f 05 06 08 14 05 38 02 01 00 14 07 ec 64 01 00 92 09 04 0a b0 59 90 05 09 07 d8 08 08 01 01 47 01 a4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_SAgnt_N_2147837781_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/SAgnt.N!MTB"
        threat_id = "2147837781"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {21 00 0b 01 13 08 10 00 a5 08 01 08 17 0a 00 00 ff ff c0 a8 a5 0a 10 03 c2 4a c2 8a 2a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_SAgnt_P_2147927315_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/SAgnt.P!MTB"
        threat_id = "2147927315"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6e 10 0d 00 ?? 00 0c 02 1a 03 ?? 00 71 10 ?? 00 03 00 0c 03 70 30 ?? 00 21 03 6e 10 ?? 00 01 00 1c 02 08 00 1a 03 ?? 00 71 10 ?? 00 03 00 0c 03 12 04 6e 30}  //weight: 1, accuracy: Low
        $x_1_2 = {4d 12 0f 04 4d 05 0f 02 13 11 03 00 4d 0d 0f 11 6e 20 ?? 00 f9 00 0c 0f 6e 10 ?? 00 07 00 0c 12 23 00 ?? 00 4d 12 00 03 62 12 ?? 00 4d 12 00 04 13 10 00 00 4d 10 00 02 13 10 03 00 4d 0b 00 10 6e 20 ?? 00 0f 00 0c 01 28 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

