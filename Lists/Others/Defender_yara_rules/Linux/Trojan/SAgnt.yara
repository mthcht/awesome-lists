rule Trojan_Linux_SAgnt_A_2147825987_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/SAgnt.A!xp"
        threat_id = "2147825987"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "SAgnt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 89 e5 48 81 ec c0 00 00 00 48 89 bd 48 ff ff ff 48 89 b5 40 ff ff ff c7 45 fc 01 00 00 00 c7 45 f8 00 00 00 00 48 8d 95 50 ff ff ff 48 8b 85 48 ff ff ff 48 89 d6 48 89 c7}  //weight: 1, accuracy: High
        $x_1_2 = {2e 30 00 77 72 69 74 65 00 72 65 61 64 00 5f 5f 65 72 72 6e 6f 5f 6c 6f 63 61 74 69 6f 6e 00 66 6f 72 6b 00 6c}  //weight: 1, accuracy: High
        $x_1_3 = {48 89 e5 48 83 ec 20 89 7d ec 48 89 75 e0 89 55 e8 c7 45 fc 00 00 00 00 c7 45 fc 00 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Linux_SAgnt_B_2147828996_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/SAgnt.B!xp"
        threat_id = "2147828996"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "SAgnt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sysCmdClientInit" ascii //weight: 1
        $x_1_2 = "sendSysCmdReq" ascii //weight: 1
        $x_1_3 = "CreateNtpPacket" ascii //weight: 1
        $x_1_4 = "netPortDetect.c" ascii //weight: 1
        $x_1_5 = "create_detect_daemon" ascii //weight: 1
        $x_1_6 = "Request cmd is udp" ascii //weight: 1
        $x_1_7 = "begain Filtering" ascii //weight: 1
        $x_1_8 = "begain SendingData" ascii //weight: 1
        $x_1_9 = "Request cmd is connect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Linux_SAgnt_D_2147828997_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/SAgnt.D!xp"
        threat_id = "2147828997"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "SAgnt"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 83 ec 20 89 7d ec 48 ?? ?? e0 be 01 00 00 00 bf 11 00 00 00 e8 89 fd ff ff bf a7 0c 40 00 e8 ?? ?? ff ff 48 8b 45 e0 48 8b 00 48 89 c7 e8 ?? ?? ff ff 48 89 c2 b9 a9 0c 40 00 48 8b 45 e0 48 8b 00 48 89 ce 48 89 c7}  //weight: 1, accuracy: Low
        $x_1_2 = {48 c1 e0 03 48 03 45 e0 48 8b 00 48 89 c7 e8 ?? ?? ff ff 48 89 c2 8b 45 fc 48 98 48 c1 e0 03 48 03 45 e0 48 8b 00 be 20 00 00 00 48 89 c7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_SAgnt_B_2147831481_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/SAgnt.B!MTB"
        threat_id = "2147831481"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BotsConnected" ascii //weight: 1
        $x_1_2 = "BOTKILL" ascii //weight: 1
        $x_1_3 = "KILLATTK" ascii //weight: 1
        $x_1_4 = "BotListener" ascii //weight: 1
        $x_1_5 = "BotWorker" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Linux_SAgnt_C_2147846768_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/SAgnt.C!MTB"
        threat_id = "2147846768"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "main.WriteReadme" ascii //weight: 2
        $x_2_2 = "main.ChangePassword" ascii //weight: 2
        $x_1_3 = "/root/bot/main.go" ascii //weight: 1
        $x_1_4 = "patchbot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Linux_SAgnt_E_2147849912_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/SAgnt.E!MTB"
        threat_id = "2147849912"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 89 e5 bf 00 00 00 00 b8 00 00 00 00 e8 e0 fe ff ff bf 00 00 00 00 b8 00 00 00 00 e8 c1 fe ff ff ba 00 00 00 00 be 90 06 40 00 bf 95 06 40 00 b8 00 00 00 00 e8 c8 fe ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_SAgnt_D_2147850527_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/SAgnt.D!MTB"
        threat_id = "2147850527"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 24 00 18 03 00 74 13 10 1d 16 89 47 c1 57 23 a5 ea 63 bc 5d a3 8b 89 f8 fd 2a 56 96 16 a1 0f 69 51 47 2a 01 37 ec 10 6d b8 e3 e4 10 9f 3e 27 be 82 81 94 d9 e7 33 a5 65 6d 7a b8 7f 6a 5a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_SAgnt_F_2147891310_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/SAgnt.F!MTB"
        threat_id = "2147891310"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8d 35 cc 07 00 00 48 8d 3d c7 07 00 00 ba 01 00 00 00 e8 59 f7 ff ff 48 8b 44 24 48 48 8d bc 24 30 02 00 00 31 d2 48 8b 30 31 c0 e8 a0 f5 ff ff 89 c7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_SAgnt_G_2147891313_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/SAgnt.G!MTB"
        threat_id = "2147891313"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 84 24 a8 08 00 00 48 83 c0 01 0f b6 00 3c 45 0f 85 b8 00 00 00 48 8b 84 24 a8 08 00 00 48 83 c0 02 0f b6 00 3c 4c 0f 85 a1 00 00 00 48 8b 84 24 a8 08 00 00 48 83 c0 03 0f b6 00 3c 46}  //weight: 1, accuracy: High
        $x_1_2 = {4c 8b 4c 24 10 48 8b 3d e0 1f 1d 00 31 c0 4c 8d 05 f8 cc 15 00 48 8d 0d ab cd 15 00 48 8d 15 06 cd 15 00 be 01 00 00 00 e8 f7 3e ff ff 48 8b 7c 24 10 48 39 df}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Linux_SAgnt_H_2147893752_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/SAgnt.H!MTB"
        threat_id = "2147893752"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {71 0c 0e 1b 94 a1 c1 a7 85 fb e8 48 60 88 de 98 58 8c 1b b4 5d 97 bc 3e f4 71 44 77 bf 67 92 53 56 a9 6d 60 13 c7 0d d4 1a 12 b0 60 a7 f8 cb ba}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_SAgnt_L_2147922856_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/SAgnt.L!MTB"
        threat_id = "2147922856"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 76 08 48 89 fa 48 81 fe ?? 85 72 00 74 15 31 c0 80 3e 2a 74 12 bf ?? 85 72 00 b9 18 00 00 00 f3 a6 75 04 ?? ?? ?? ?? f3 c3 0f 1f 44 00 00}  //weight: 1, accuracy: Low
        $x_2_2 = {95 d1 ff 70 95 d1 ff 70 95 d1 ff 70 95 d1 ff 70 95 d1 ff 70 95 d1 ff 70 95 d1 ff 70 95 d1 ff 70 95 d1 ff 70 95 d1 ff 70 95 d1 ff 70 95 d1 ff 70 95 d1 ff 70 95 d1 ff 70 95 d1 ff 70 95 d1 ff 70 95 d1 ff 70 95 d1 ff 70 95 d1 ff 48 95 d1 ff 70 95 d1 ff 70 95 d1 ff 48 95 d1 ff 70 95 d1 ff 70 95 d1 ff 70 95 d1 ff 70 95 d1 ff 70 95 d1 ff 70 95 d1 ff 70 95 d1 ff 70 95 d1 ff 70 95 d1 ff 70 95 d1 ff 70 95 d1 ff 70 95 d1 ff 70 95 d1 ff 70}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_SAgnt_M_2147922857_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/SAgnt.M!MTB"
        threat_id = "2147922857"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {50 52 e8 49 0b 00 00 55 53 51 52 48 01 fe 56 48 29 fe 41 80 f8 0e 0f 85 67 0a 00 00 55 48 89 e5 44 8b 09 49 89 d0 48 89 f2 ?? ?? ?? ?? 56 8a 07 ff ca 88 c1 24 07 c0 e9 03 48 c7 c3 00 fd ff ff 48 d3 e3 88 c1}  //weight: 2, accuracy: Low
        $x_1_2 = {48 8b 54 24 e8 44 89 f8 44 29 f0 44 0f b6 2c 02 44 89 f8 41 ff c7 ff cd 44 88 2c 02 0f 95 c2 31 c0 44 3b 7c 24 e4 0f 92 c0 85 c2 75 d3 44 3b 7c 24 e4 0f 82 45 f7 ff ff 41 81 fb ff ff ff 00 77 16 4c 39 e7 b8 01 00 00 00 74 23 eb 07}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_SAgnt_N_2147924461_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/SAgnt.N!MTB"
        threat_id = "2147924461"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {be 10 37 4b 01 48 81 ee 10 37 4b 01 48 89 f0 48 c1 ee 3f 48 c1 f8 03 48 01 c6 48 d1 fe 74 ?? b8 00 00 00 00 48 85 c0 74 ?? bf 10 37 4b 01 ff e0}  //weight: 1, accuracy: Low
        $x_1_2 = {41 0f 94 c2 48 83 fa 07 75 ?? 44 0f b7 1c 38 66 41 81 fb 61 6c 75 ?? 0f b6 7c 38 02 ?? 40 80 ff 6c 75 ?? 48 8b 3d eb e0 2d 01 31 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_SAgnt_O_2147926126_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/SAgnt.O!MTB"
        threat_id = "2147926126"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vxshell/src/httpsclient/client.go" ascii //weight: 1
        $x_1_2 = "task.startSocks" ascii //weight: 1
        $x_1_3 = "task.executeCmd" ascii //weight: 1
        $x_1_4 = "/forward.NewShellClient" ascii //weight: 1
        $x_1_5 = "/scan.portConnect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_SAgnt_Q_2147928566_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/SAgnt.Q!MTB"
        threat_id = "2147928566"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {be a8 12 60 00 55 48 81 ee a8 12 60 00 48 c1 fe 03 48 89 e5 48 89 f0 48 c1 e8 3f 48 01 c6 48 d1 fe 74 15 b8 00 00 00 00 48 85 c0 74 0b 5d bf a8 12 60 00 ff e0 0f 1f 00 5d c3 66 0f 1f 44 00 00 80 3d a9 06 20 00 00 75 11 55 48 89 e5 e8 6e ff ff ff 5d c6 05 96 06 20 00 01 f3 c3 0f 1f 40 00 bf 10 10 60 00 48 83 3f 00 75 05 eb 93 0f 1f 00 b8 00 00 00 00 48 85 c0 74 f1 55 48 89 e5 ff d0 5d e9 7a ff ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {e8 00 ff ff ff ff c0 75 0c bf 0a 00 00 00 e8 02 ff ff ff eb df 31 c9 ba 06 00 00 00 be e4 0c 40 00 89 df e8 2d fe ff ff 66 8b 44 24 1e 48 8d 74 24 02 31 c9 ba 02 00 00 00 89 df 88 44 24 02 66 c1 e8 08 88 44 24 03 e8 09 fe ff ff 48 8d 74 24 2f 31 c9 ba 20 00 00 00 89 df e8 f6 fd ff ff 31 d2 31 c0 be eb 0c 40 00 bf 3f 01 00 00 e8 43 fe ff ff 85 c0 41 89 c4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_SAgnt_R_2147931784_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/SAgnt.R!MTB"
        threat_id = "2147931784"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 48 89 e5 e8 7c af fe ff 8b 00 83 f8 73 0f 94 c0 c9 c3}  //weight: 1, accuracy: High
        $x_1_2 = {48 89 c7 e8 9d 0d 00 00 83 45 c4 01 8b 45 c4 3b 85 1c ff ff ff 0f 9c c0 84 c0 0f ?? ?? ?? ?? ?? 48 81 c4 f0 00 00 00 5b 41 5c c9 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_SAgnt_S_2147935645_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/SAgnt.S!MTB"
        threat_id = "2147935645"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 c9 ba 00 10 00 00 48 89 ee 89 df e8 08 fd ff ff 85 c0 48 89 c2 89 c1 7e 21 48 89 e8 80 30 99 48 ff c0 89 c6 29 ee 39 ce 7c f2 48 63 d2 48 89 ee 44 89 ef}  //weight: 1, accuracy: High
        $x_1_2 = {31 c0 b9 00 04 00 00 48 89 ef f3 ab 89 df e8 1b fd ff ff 49 8b 3c 24 48 8d b4 24 30 08 00 00 31 c0 e8 78 fd ff ff 48 8d b4 24 30 08 00 00 ba 01 00 00 00 bf 52 0e 40 00 31 c0 e8 bf fc ff ff 48 8b 15 d8 06 20 00 48 8d 74 24 10 44 89 ef 31 c0 48 c7 44 24 10 56 0e 40 00 48 c7 44 24 18 00 00 00 00 e8 07 fd ff ff 89 df e8 c0 fc ff ff 48 81 c4 38 1c 00 00 31 c0 5b 5d 41 5c 41 5d c3}  //weight: 1, accuracy: High
        $x_1_3 = {66 44 8b 4c 24 22 41 b8 c5 0d 40 00 66 41 c1 c9 08 45 0f b7 c9 48 89 ef b9 a4 0d 40 00 41 51 68 a4 0d 40 00 ba c9 0d 40 00 be cd 0d 40 00 31 c0 e8 a7 fe ff ff 31 c9 ba 00 04 00 00 48 89 ee 89 df e8 f6 fd ff ff 31 c0 48 89 ef b9 00 01 00 00 f3 ab 31 ed 58}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_SAgnt_U_2147942906_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/SAgnt.U!MTB"
        threat_id = "2147942906"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 d2 45 85 ed 41 51 49 89 d8 6a 00 0f 95 c2 4c 89 e1 45 31 c9 48 c1 e2 07 48 89 ee bf ca 00 00 00 e8 41 b5 ff ff 41 5a 41 5b 83 f8 da 75 1e 56 49 89 d8 bf ca 00 00 00 45 31 c9 6a 00 4c 89 e1 31 d2 48 89 ee}  //weight: 1, accuracy: High
        $x_1_2 = {4c 89 ff 4c 89 e1 48 8d 15 10 e5 00 00 31 c0 be 80 10 00 00 e8 e2 5f 00 00 4c 89 ff e8 0c 52 00 00 4c 89 f2 4c 89 ee 4c 89 e7 e8 8c 50 00 00 e9 2d ff ff ff 66 0f 1f 84 00 00 00 00 00 4c 89 e6 4c 89 ff e8 a5 8c 00 00 48 85 c0 0f 85 ac 00 00 00 31 d2 be 80 10 00 00 4c 89 ff e8 b8 58 00 00 48 85 c0 75 d8 31 ff}  //weight: 1, accuracy: High
        $x_1_3 = {41 0f b6 4f 01 b8 00 03 00 00 41 02 0f d3 e0 49 8b 77 08 8d 88 c0 07 00 00 48 85 c9 0f 84 a5 00 00 00 48 8d 41 ff 48 83 f8 06 0f 86 fd 02 00 00 48 89 ca 66 0f 6f 05 c5 b3 00 00 48 89 f0 48 c1 ea 03 48 c1 e2 04 48 01 f2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_SAgnt_X_2147943285_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/SAgnt.X!MTB"
        threat_id = "2147943285"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 1d 8d e2 30 10 81 e2 01 2a a0 e3 05 00 a0 e1 8d 26 00 eb 81 1d 8d e2 30 10 81 e2 00 20 50 e2 04 00 a0 e1 f4 ff ff ca 05 00 a0 e1 35 26 00 eb 04 00 a0 e1 33 26 00 eb 08 10 8d e2 70 00 8d e2 73 15 00 eb 01 00 70 e3 75 ff ff 0a 41 0d 8d e2 18 10 9d e5 30 00 80 e2 63 15 00 eb 01 00 70 e3}  //weight: 1, accuracy: High
        $x_1_2 = {00 20 93 e5 01 00 52 e3 f9 ff ff 1a 08 c0 93 e5 14 20 93 e5 0c 00 50 e1 02 20 8c e0 0c 00 a0 21 20 30 83 e2 02 00 51 e1 02 10 a0 31 0e 00 53 e1 f2 ff ff 3a ff 3e 81 e2 0f 30 83 e2 ff 3e c3 e3 ff 6e c0 e3 0f 30 c3 e3 0f 60 c6 e3 03 60 66 e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_SAgnt_W_2147943291_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/SAgnt.W!MTB"
        threat_id = "2147943291"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 44 24 50 8b 74 24 10 c7 44 24 0c 00 00 00 00 89 30 31 f6 89 58 04 8b 44 24 0c 89 f2 83 c4 2c 5b 5e 5f 5d c3 0f bd f7 83 f6 1f}  //weight: 1, accuracy: High
        $x_1_2 = {53 89 c3 83 ec 08 8b 40 4c 85 c0 78 0c 83 ec 0c 53 e8 fe e9 ff ff 83 c4 10 8b 43 1c 39 43 14 74 0c 51 6a 00 6a 00 53 ff 53 24 83 c4 10 8b 43 04 8b 53 08 39 d0}  //weight: 1, accuracy: High
        $x_1_3 = {0f b6 47 0c ba 27 00 00 00 89 c1 83 e1 0f 0f a3 ca 73 75 c0 e8 04 b9 06 04 00 00 0f a3 c1 73 68 66 83 7f 0e 00 74 61 8b 07 83 ec 08 01 e8 50 ff 74 24 50 8b 5c 24 28 e8 84 9c ff ff 83 c4 10 85 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_SAgnt_Z_2147943545_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/SAgnt.Z!MTB"
        threat_id = "2147943545"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3b a3 00 14 39 00 00 00 38 e0 ff ff 38 c0 00 22 38 a0 00 03 7f a4 eb 78 38 60 00 00 48 00 03 45 60 00 00 00 2c 23 ff ff 7c 7e 1b 78 41 82 ff c8 4b ff f3 29 4b ff f3 79 4b ff f4 31 7c 7f 1b 79 40 82 00 28 60 00 00 00 38 62 89 10 48 00 61 d1 60 00 00 00 7f a4 eb 78 7f c3 f3 78 48 00 04 65}  //weight: 1, accuracy: High
        $x_1_2 = {3b c0 00 02 39 00 00 00 38 e0 ff ff e9 22 85 a0 38 c0 00 22 38 a0 00 00 38 60 00 00 7f de 48 36 7c 9f f1 d2 48 00 0c 29 60 00 00 00 2c 23 ff ff 41 82 fe d8 60 00 00 00 7c 63 fa 14 3b de ff ff f8 62 85 b8 7b e9 a3 02 7f de 49 d2 60 00 00 00 fb c2 85 98 e9 22 85 a0 39 29 00 01 f9 22 85 a0}  //weight: 1, accuracy: High
        $x_1_3 = {39 03 00 01 55 0a f8 7e 55 09 f0 be 7d 29 53 78 55 2a f0 be 7d 29 53 78 55 2a e1 3e 7d 29 53 78 55 2a c2 3e 7d 29 53 78 55 2a 84 3e 7d 29 53 78 39 49 00 01 7d 49 48 78 3d 40 07 6b 61 4a e6 29 7d 29 51 d6 3d 42 ff fe 39 4a a3 18 79 29 2e e2 7c 6a 48 ae 3d 42 ff fe 39 4a a2 b8 38 63 ff ff 54 63 10 3a 39 23 00 01 7d 29 07 b4 79 29 0f a4 7d 2a 4a 2e 7c 29 40 40}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_SAgnt_V_2147943673_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/SAgnt.V!MTB"
        threat_id = "2147943673"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 31 ed 48 89 e7 48 8d 35 2a 46 27 00 48 83 e4 f0 e8 00 00 00 00 48 81 ec 90 01 00 00 8b 07 49 89 f8 48 89 f1 ff c0 48 98}  //weight: 1, accuracy: High
        $x_1_2 = {44 89 fa 31 c0 48 89 54 24 08 e8 9f 4e 06 00 44 89 ff 48 89 04 24 e8 6e d9 06 00 31 c0 e8 8c 4e 06 00 48 8b 0c 24 48 8b 54 24 08 48 29 c8 78 78 66 0f ef c0 f2 48 0f 2a c0}  //weight: 1, accuracy: High
        $x_1_3 = {4c 8d 25 96 03 00 00 4c 89 e7 e8 ce 50 06 00 4c 89 e7 48 8d 74 24 18 e8 f1 50 06 00 41 89 c4 85 c0 75 a1 48 83 7c 24 18 00 0f 84 06 01 00 00 80 3d 4f 49 27 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Linux_SAgnt_Y_2147943677_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/SAgnt.Y!MTB"
        threat_id = "2147943677"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e0 03 00 90 00 e8 47 f9 26 94 01 94 e0 03 00 90 00 e8 47 f9 e1 a3 01 91 32 94 01 94 c0 fc ff 35 e0 37 40 f9 20 05 00 b4 03 03 00 91 60 60 40 39}  //weight: 1, accuracy: High
        $x_1_2 = {fd 7b b9 a9 fd 03 00 91 f3 53 01 a9 f7 63 03 a9 f8 03 00 b0 13 03 00 91 f7 03 00 2a f5 5b 02 a9 f6 03 02 aa 60 12 40 b9 f5 03 01 aa a1 a7 01 94 e1 03 00 2a 60 06 40 b9 61 12 00 b9 9d a7 01 94}  //weight: 1, accuracy: High
        $x_1_3 = {fd 7b be a9 fd 03 00 91 f3 0b 00 f9 f3 03 00 b0 60 c2 4e 39 40 01 00 37 de ff ff 97 e0 03 00 90 00 c8 47 f9 80 00 00 b4 c0 03 00 f0 00 c0 1d 91}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Linux_SAgnt_AC_2147945380_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/SAgnt.AC!MTB"
        threat_id = "2147945380"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 00 3f 89 01 00 ff 38 00 00 09 2c 14 01 82 40 78 53 43 7d 45 8d 00 48 00 00 00 60 e8 00 61 e8 f1 fe ff 4b 00 00 00 60 78 00 41 e9 80 00 21 e9 00 48 2a 7c 20 00 82 40 88 00 41 e9 90 00 21 e9 00 48 2a 7c 10 00 82 40 d8 00 21 e9 00 00 29 2c}  //weight: 1, accuracy: High
        $x_1_2 = {b4 07 fb 7f d2 c1 7b 7f 10 00 5b 39 40 48 2a 7c cc 04 81 40 f9 ff 5c 39 00 00 80 3a 1f 00 0a 28 54 00 81 41 b4 07 4a 7d 14 52 5d 7d 50 03 0a 89 70 03 2a 89 00 00 08 2c 3e 06 34 55 3e 06 27 55 63 00 94 22 e0 0f 94 7a 2c 00 82 41 00 00 00 60 00 89 c2 88 50 30 08 7d 09 00 08 2c 18 00 81 41 62 00 07 28 01 00 29 39 08 00 81 40 96 ff 20 39}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_SAgnt_AD_2147946393_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/SAgnt.AD!MTB"
        threat_id = "2147946393"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 8f f2 ff 14 e8 82 0b fe ff 49 8b 41 08 49 8b 11 49 81 e9 08 00 00 00 48 0f ab dd 66 d3 d5 48 f7 e2 48 0f b7 ee 49 0f bf ec 49 89 51 08 41 0f b7 ee 66 f7 d5 49 0f b7 eb 49 89 41 10 9c 40 86 ed 66 d1 cd 41 8f 01 40 d2 cd 49 0b eb 49 81 eb 04 00 00 00 41 02 ec f5 40 d2 ed 41 8b 2b 41 3b dc f5 f9 33 ee 81 c5 1c 68 f3 3c f9 f8 d1 cd 66 f7 c3 2b 7e 0f cd 80 fa 1d f7 dd f8}  //weight: 1, accuracy: High
        $x_1_2 = {56 44 31 14 24 66 44 85 cb 66 41 0f b6 f1 f8 5e 4d 63 d2 f9 f5 e9 db 46 fd ff 81 f2 36 43 32 1c 41 51 41 f6 c7 4d 31 14 24 41 59 48 63 d2 45 3a e6 f9 4c 03 d2 e9 96 c6 00 00 f7 d1 e9 1c 7a 00 00 49 0f ba e0 39 31 0c 24 41 80 c0 51 49 c1 d8 89 44 1a c6 41 58 f6 c7 71 48 63 c9 45 3a e4 4c 03 d1 e9 60 fc 32 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

