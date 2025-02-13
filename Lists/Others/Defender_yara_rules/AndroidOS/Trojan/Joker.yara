rule Trojan_AndroidOS_Joker_A_2147743929_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Joker.A"
        threat_id = "2147743929"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Joker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "3.122.143.26" ascii //weight: 1
        $x_1_2 = "api/ckwkc2?icc=" ascii //weight: 1
        $x_1_3 = "DexClassLoader" ascii //weight: 1
        $x_1_4 = "loadClass" ascii //weight: 1
        $x_1_5 = "getClassLoader" ascii //weight: 1
        $x_1_6 = "getDeclaredMethod" ascii //weight: 1
        $x_1_7 = "cWdQfEpRgTrYsUhIiOyPlAmSvDwFtGzHjJkKuLaZbXeCxVnBoNqM" ascii //weight: 1
        $x_1_8 = "2ba42a014f0c8e92" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Trojan_AndroidOS_Joker_B_2147759468_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Joker.B!MTB"
        threat_id = "2147759468"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Joker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "gd-1301476296.cos.na-toronto.myqcloud.com" ascii //weight: 3
        $x_1_2 = "baobutong" ascii //weight: 1
        $x_1_3 = "bpilong" ascii //weight: 1
        $x_1_4 = "poroc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_Joker_C_2147783178_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Joker.C"
        threat_id = "2147783178"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Joker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fb_version_id" ascii //weight: 1
        $x_1_2 = "HkOnTouchLitener" ascii //weight: 1
        $x_1_3 = "Lcn/mhok/sdjk/FacebookUtils" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Joker_D_2147783179_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Joker.D"
        threat_id = "2147783179"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Joker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MSG_TASK_PROGRESS" ascii //weight: 1
        $x_1_2 = "MSG_TASK_MERGE_FILE:" ascii //weight: 1
        $x_1_3 = "mChildSuccessTimes:" ascii //weight: 1
        $x_1_4 = "--MSG_DONWLOAD" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Joker_OA_2147785259_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Joker.OA"
        threat_id = "2147785259"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Joker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "http://3.122.143.26/api/ckwksl?icc=" ascii //weight: 2
        $x_2_2 = "Lcom/startapp/android/publish" ascii //weight: 2
        $x_2_3 = "Remote Cloak" ascii //weight: 2
        $x_2_4 = "cloaked: no more trial" ascii //weight: 2
        $x_2_5 = "cWdQfEpRgTrYsUhIiOyPlAmSvDwFtGzHjJkKuLaZbXeCxVnBoNqM" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_AndroidOS_Joker_2147788032_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Joker.pb"
        threat_id = "2147788032"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Joker"
        severity = "Critical"
        info = "pb: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "com.coolringting.ringtonesmaker" ascii //weight: 2
        $x_2_2 = "KxsbHBp9Rl9UWl1cXV0RHxZjU1pKCycIQB9EOhwH" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Joker_E_2147789038_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Joker.E!MTB"
        threat_id = "2147789038"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Joker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = ".aliyuncs.com/" ascii //weight: 2
        $x_2_2 = "rquestPhonePermission" ascii //weight: 2
        $x_2_3 = "com.antume.Cantin" ascii //weight: 2
        $x_1_4 = "startSDK" ascii //weight: 1
        $x_1_5 = "cancelAllNotifications" ascii //weight: 1
        $x_1_6 = "getDefaultSmsPackage" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_Joker_F_2147789102_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Joker.F"
        threat_id = "2147789102"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Joker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "getEvinaData-----url:" ascii //weight: 1
        $x_1_2 = "moSendSMS:" ascii //weight: 1
        $x_1_3 = "mcp_stringBuilder--null" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Joker_S_2147806267_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Joker.S"
        threat_id = "2147806267"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Joker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {18 00 ff ff ff ff 00 00 00 00 c0 b0 71 20 8c d6 10 00 0b 00 71 20 8a d6 10 00 0b 00 13 02 20 00 a5 03 00 02 17 05 ff ff 00 00 c0 53 71 20 8a d6 10 00 0b 00 13 07 10 00 a5 07 00 07 17 09 00 00 ff ff c0 97 c5 2b c2 3b c2 7b 84 bc 71 40 84 d6 dc 10 0b 00 a5 03 00 02 c0 53 84 3b 23 b3 b6 2d 12 04 35 b4 14 00 90 07 0c 04 d8 07 07 01 71 40 84 d6 d7 10 0b 00 a5 07 00 02 c0 57 84 78 8e 87 50 07 03 04 d8 04 04 01 28 ed 22 0b ba 2a 70 20 73 df 3b 00 11 0b}  //weight: 1, accuracy: High
        $x_1_2 = {17 00 ff ff 00 00 a0 02 04 00 84 23 8f 32 13 03 10 00 c5 34 c0 04 84 45 8f 54 90 05 02 04 8f 55 13 00 09 00 71 20 8b d6 05 00 0a 05 b0 25 8f 55 b7 24 8f 44 13 00 0d 00 71 20 8b d6 02 00 0a 00 b7 40 8f 00 e0 01 04 05 b7 10 8f 00 13 01 0a 00 71 20 8b d6 14 00 0a 04 81 51 c3 31 81 44 c1 14 c3 34 81 00 c1 04 10 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Joker_QA_2147806268_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Joker.QA"
        threat_id = "2147806268"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Joker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "evina=2post" ascii //weight: 1
        $x_1_2 = "nextportal.hlifeplus.com/wap/api_aoc" ascii //weight: 1
        $x_1_3 = "web-zmd.secure-d.io/api/v2/activate" ascii //weight: 1
        $x_1_4 = "MCP_OUTLINE_KEY" ascii //weight: 1
        $x_1_5 = "Failed to detect incline mcp code" ascii //weight: 1
        $x_1_6 = "cp_call_center_number" ascii //weight: 1
        $x_1_7 = "MCP_SITE.r.shield.monitoringservice.co/p.png" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_AndroidOS_Joker_P_2147807746_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Joker.P"
        threat_id = "2147807746"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Joker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wo0.oss-accelerate.aliyuncs.com/adal.jar" ascii //weight: 1
        $x_1_2 = "com.antume.Cantin" ascii //weight: 1
        $x_1_3 = "io_fv.log" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Joker_O_2147807747_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Joker.O"
        threat_id = "2147807747"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Joker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {67 75 6f 2f 73 6d 73 63 6f 6c 6f 72 2f 61 6d 65 73 73 61 67 65 2f 75 74 69 6c 73 2f 54 68 00 63 68 65 63 6b}  //weight: 1, accuracy: High
        $x_1_2 = "all.free.R" ascii //weight: 1
        $x_1_3 = "63006F006D002E006500780061006D0070006C0065002E006200610073006500" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Joker_F_2147812531_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Joker.F!MTB"
        threat_id = "2147812531"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Joker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VOICEMANAGER_PHONENUMBER_RECORD_TYPE" ascii //weight: 1
        $x_3_2 = "_77g7_h/_77g7_h" ascii //weight: 3
        $x_1_3 = "logoutSMSNumber" ascii //weight: 1
        $x_1_4 = "READ_CALL_LOG" ascii //weight: 1
        $x_1_5 = "TRACK_NUMBER" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_Joker_J_2147813022_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Joker.J!MTB"
        threat_id = "2147813022"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Joker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0c 0e 12 0f 71 20 ?? ?? fe 00 0c 04 22 0a ?? ?? 6e 10 ?? ?? 0c 00 0c 0e 70 20 ?? ?? ea 00 22 07 ?? ?? 70 20 ?? ?? 47 00 12 08 6e 10 ?? ?? 07 00 0a 08 12 fe 32 e8 ?? ?? 14 0e 40 e2 01 00 b7 8e 6e 20 ?? ?? ea 00}  //weight: 1, accuracy: Low
        $x_1_2 = "com/keyyt/board/lofutrnhsuos" ascii //weight: 1
        $x_1_3 = {70 73 3a 2f 2f [0-20] 2e 73 33 2e 75 73 2d 77 65 73 74 2d 32 2e 61 6d 61 7a 6f 6e 61 77 73 2e 63 6f 6d 2f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Joker_K_2147816689_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Joker.K!MTB"
        threat_id = "2147816689"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Joker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {1a 00 39 09 6e 20 f6 09 05 00 0c 05 21 50 12 01 35 01 32 00 46 02 05 01 6e 10 01 0a 02 00 0c 03 1a 04 bc 27 6e 20 f7 09 43 00 0a 03 38 03 21 00 1a 03 6c 09 6e 20 f6 09 32 00 0c 02 21 23 12 14 37 43 17 00 46 05 02 04 6e 10 01 0a 05 00 0c 05 1a 00 00 00 1a 01 3d 03 6e 30 f5 09 15 00 0c 05 1a 01 b5 04 6e 30 f5 09 15 00 0c 05 11 05 d8 01 01 01 28 cf 12 05 11 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Joker_K_2147816689_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Joker.K!MTB"
        threat_id = "2147816689"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Joker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {12 1c 12 0b 12 29 23 94 ?? ?? 71 20 ?? ?? fd 00 0c 09 4d 09 04 0b 71 20 ?? ?? fe 00 0c 09 4d 09 04 0c 46 09 04 0b 6e 10 ?? ?? 09 00 0c 09 1a 0a 40 00 6e 20 ?? ?? a9 00 0c 00 6e 20 ?? ?? c0 00 46 09 04 0b 71 20 ?? ?? 09 00 0c 07}  //weight: 2, accuracy: Low
        $x_2_2 = {12 20 23 00 2d 00 71 20 ?? ?? ec 00 0c 01 12 02 4d 01 00 02 71 20 ?? ?? ed 00 0c 01 12 13 4d 01 00 03 46 01 00 02 6e 10 ?? ?? 01 00 0c 01 1a 04 69 00 6e 20 ?? ?? 41 00 0c 01 6e 20 ?? ?? 31 00 46 01 00 02 46 05 00 02 6e 10 ?? ?? 05 00 0c 05 6e 20 ?? ?? 45 00 0c 05 71 20 ?? ?? 51 00 0c 01}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_AndroidOS_Joker_D_2147817431_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Joker.D!MTB"
        threat_id = "2147817431"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Joker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {12 00 1a 03 00 00 1a 02 00 00 01 01 13 04 0f 00 34 41 24 00 22 01 ?? ?? 6e 10 ?? ?? 08 00 0a 04 db 04 04 02 70 20 ?? ?? 41 00 6e 10 ?? ?? 08 00 0a 04 3c 04 ?? ?? 6e 10 ?? ?? 01 00 0c 01 21 13 6e 10 ?? ?? 02 00 0a 04 34 30 54 00 22 00 ?? ?? 70 20 ?? ?? 10 00 11 00 22 04 ?? ?? 70 10 ?? ?? 04 00 6e 20 ?? ?? 34 00}  //weight: 2, accuracy: Low
        $x_2_2 = {0c 03 71 10 cb 2e 01 00 0c 04 6e 20 ?? ?? 43 00 0c 03 6e 10 ?? ?? 03 00 0c 03 22 04 0b 08 70 10 ?? ?? 04 00 6e 20 ?? ?? 24 00 0c 02 71 00 ?? ?? 00 00 0b 04 13 06 0a 00 83 66 cd 64 8a 44 b7 14 6e 20 ?? ?? 42 00 0c 02 6e 10 ?? ?? 02 00 0c 02 d8 01 01 01 28 a8 12 e4 6e 20 ?? ?? 48 00 0a 04 6e 20 ?? ?? 43 00 0a 04 e0 04 04 04 12 f5 6e 20 ?? ?? 58 00 0a 05 6e 20 ?? ?? 53 00 0a 05 b6 54 6e 20 ?? ?? 41 00 28 9e 48 05 01 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Joker_M_2147835604_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Joker.M!MTB"
        threat_id = "2147835604"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Joker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "://ss1.mobilelife.co.th" ascii //weight: 2
        $x_1_2 = "confirmOtp" ascii //weight: 1
        $x_1_3 = "/op/pair?remote=" ascii //weight: 1
        $x_1_4 = "loadClass" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_Joker_N_2147836798_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Joker.N!MTB"
        threat_id = "2147836798"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Joker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = ".aliyuncs.com/cxjus" ascii //weight: 3
        $x_1_2 = "getClassLoader" ascii //weight: 1
        $x_1_3 = "rquestPhonePermission" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_Joker_O_2147837780_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Joker.O!MTB"
        threat_id = "2147837780"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Joker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 6f 73 73 2d [0-16] 2d 31 2e 61 6c 69 79 75 6e 63 73 2e 63 6f 6d 2f}  //weight: 1, accuracy: Low
        $x_1_2 = "dxoptFile" ascii //weight: 1
        $x_1_3 = "baos" ascii //weight: 1
        $x_1_4 = "DexClassLoader" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

