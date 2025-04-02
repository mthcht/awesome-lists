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

rule TrojanDropper_AndroidOS_SAgnt_Q_2147934091_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/SAgnt.Q!MTB"
        threat_id = "2147934091"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {77 00 b4 00 00 00 0c 1a 14 1d d3 bf 1a 00 77 00 fc 01 00 00 0c 19 77 01 b8 00 19 00 0a 19 97 1d 1d 19 14 1b 76 bc 1a 00 77 00 a5 01 00 00 0c 19 77 01 b8 00 19 00 0a 19 97 1b 1b 19 14 1c 69 be 1a 00 77 00 a3 02 00 00 0c 19 77 01 b8 00 19 00 0a 19 97 1c 1c 19 77 04 c2 00 1a 00 0c 1a 08 03 1a 00 12 05 71 20 c9 01 53 00 0c 03 71 20 97 01 34 00 0a 03 38 03 42 00 77 00 b4 00 00 00 0c 1e 14 21 c7 ab 1a 00 77 00 27 02 00 00 0c 1d 77 01 b8 00 1d 00 0a 1d 97 21 21 1d 14 1f 7c cb 1a 00 77 00 37 02 00 00 0c 1d 77 01 b8 00 1d 00 0a 1d 97 1f 1f 1d 14 20 e0 c9 1a 00}  //weight: 1, accuracy: High
        $x_1_2 = {71 00 96 01 00 00 0c 00 71 10 fb 01 00 00 0a 04 39 04 8e ff 77 00 7c 02 00 00 0c 29 14 2c ab b6 1a 00 77 00 df 01 00 00 0c 28 77 01 79 02 28 00 0a 28 97 2c 2c 28 14 2a db a7 1a 00 77 00 d9 01 00 00 0c 28 77 01 79 02 28 00 0a 28 97 2a 2a 28 14 2b 87 be 1a 00 77 00 12 02 00 00 0c 28 77 01 79 02 28 00 0a 28 97 2b 2b 28 77 04 af 02 29 00 0c 29 08 00 29 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_SAgnt_R_2147937712_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/SAgnt.R!MTB"
        threat_id = "2147937712"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {14 c1 04 91 e0 03 14 aa b5 a3 02 d1 ea 69 fe 97 40 01 80 52 e1 03 14 aa 0f 68 fe 97 b8 db 36 a9 b7 e7 35 a9 a1 02 40 ad a0 23 02 d1 e2 03 03 91 e1 03 13 aa e1 03 06 ad 1b 69 fe 97 a0 83 57 f8 fd 68 fe 97 c0 00 00 90 00 80 08 91 e1 03 1f 2a e2 03 1f 2a b4 6b fe 97 a2 83 57 f8 c1 00 00 90 21 50 09 91 40 00 80 52}  //weight: 2, accuracy: High
        $x_2_2 = {c6 10 63 f7 5d d3 5d ab 6c d4 5d ab 6c 1f 55 0a 4e d7 5d ab 6c 06 10 db 23 ac 92 cb 41 d7 5d ab 6c 30 12 54 b7 f4 88 ab f4 d8 5d ab 6c 7f bc c0 2b d8 5d ab 6c a5 76 c9 48 40 bc 4d 6a dc 0d a6 78 8b 7f 97 9a fd bc 5e ea 4b 26 43 a6 19 f4 03 32 95 1d 22 73 44 d2 7e 2e 47 0b 1a 6c 53 5e 72 dd d5 4e 25 9e 45 bd 19 7b b1 56 11 93 ba 5b 8a b8 3f ce ed ea 4f 8c ee 75 35 76 e9 68 29 ac a6 40 66 23 2a 48 c5 35 f4 e1 1b c5 97 ca 33 bd 8c 66 f9 4c 0c a4 cb 3f 7b 81 17 62 b5 86 14 55 e1 5e df 2d e3 88 45 83 ae 78 14 b0 c6 f9 7d f3 83 9a 11 52 36 36 cd a8 87 f9 bf 3e bb 6f 35 56 cd f4 28 10 d3 7d ef 33 05 b0 f0 33 05 b0 12 89 9b 9d e9 9f b4 76 8e e3}  //weight: 2, accuracy: High
        $x_1_3 = {a0 64 f5 63 aa 62 73 d7 80 83 97 a3 40 c9 b5 16 2b 3d ee f0 95 47 01 81 f0 c1 43 18 2b 3d ee 4f 91 61 4b 1b 2b 3d ee 1a 2b 3d ee 2b 5e fd 56 73 19 b3 7b fe cd 2a 25 44 32 7a 70 97 8d a9 0f 8d c3 72 dc 21 2b 3d ee 23 2b 3d ee 40 66 02 88 54 74 e2 d4 3b 08 36 c1 6d 23 41 8d 7f 6c 90 b7 28 2b 3d ee 47 b4 33 dc e3 c4 e6 c5 f0 da 10 18 2d 2b 3d ee 2e 2b 3d ee 09 27 eb b2}  //weight: 1, accuracy: High
        $x_1_4 = "01357kTDFXWUHJP;K#jQG" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_AndroidOS_SAgnt_T_2147937713_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/SAgnt.T!MTB"
        threat_id = "2147937713"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {37 5f 6a 63 6c 61 73 73 50 31 30 5f 6a 6d 65 74 68 6f 64 49 44 7a 00 4a 61 76 61 5f 6b 5f 77 7a 5f 6b 30 00 5f 5f 73 74 72 63 61 74 5f 63 68 6b 00 4a 61 76 61 5f 6b 5f 77 7a 5f 6b 31 00 4a 61 76 61 5f 6b 5f 77 7a 5f 6b 33 00 4a 61 76 61 5f 6b 5f 77 7a 5f 6b 32 00 4a 61 76 61 5f 6b 5f 77 7a 5f 6f 31 00 5f 5a 4e 37 5f 4a 4e 49 45 6e 76 32 30 43 61 6c 6c 53}  //weight: 2, accuracy: High
        $x_1_2 = {e5 93 fd 8a 6f c6 fe 8a 6f c6 da 8a 6f c6 3d 8b 6f c6 7c 14 b7 a7 78 0c de e5 3e 8b 6f c6 3f 8b 6f c6 d4 d6 b4 c6 32 91 45 0b 16 5b 0b 71 00 fe 5d c2 3f 8b 6f c6 4e 92 22 e1 6c e6 60 94 40 8b 6f c6 39 8b 6f c6 ce 2e fc 37 fa 8a 6f c6 80 8b 6f c6 b0 0b b8 0c c6 ff 28 fd 40 8b 6f c6 e3 23 82 8e d4 47 78 91 ce d6 87 0a fd 8a 6f c6 00 5f 5f 63 78 61 5f 66 69 6e 61 6c 69 7a 65 00 5f 5f 63 78 61 5f 61 74 65 78 69 74 00 5f 5f 72 65 67 69 73 74 65 72 5f}  //weight: 1, accuracy: High
        $x_1_3 = {6f 64 45 50 37 5f 6a 63 6c 61 73 73 50 31 30 5f 6a 6d 65 74 68 6f 64 49 44 7a 00 4a 61 76 61 5f 6b 5f 77 7a 5f 68 73 00 4a 61 76 61 5f 6b 5f 77 7a 5f 68 73 32 00 4a 61 76 61 5f 6b 5f 77 7a 5f 6d 30 00 66 6f 70 65 6e 00 66 77 72 69 74 65 00 66 63 6c 6f 73 65 00 4a 61 76 61 5f 6b 5f 77 7a 5f 6d 31 00 4a 61 76 61 5f 6b 5f 77 7a 5f 6d 32 00 5f 5a 4e 37 5f 4a 4e 49 45 6e 76 31 33 43 61 6c 6c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

