rule TrojanDownloader_MacOS_Adload_B_2147822253_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MacOS/Adload.B!MTB"
        threat_id = "2147822253"
        type = "TrojanDownloader"
        platform = "MacOS: "
        family = "Adload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 07 48 8b 4f 08 48 89 85 70 ff ff ff 48 89 8d 78 ff ff ff 48 8b 47 10 48 89 45 80 48 8b 85 e8 fe ff ff 48 8b 95 f0 fe ff ff 89 d1 29 c1 89 ce c1 ee 1f 01 ce d1 fe 48 63 f6 48 01 c6 e8 ?? ?? f8 ff 4c 8b 7d 90 48 8b 5d 98}  //weight: 1, accuracy: Low
        $x_1_2 = {66 0f 57 c0 48 8d 7d 90 66 0f 29 07 48 c7 47 10 00 00 00 00 48 89 de 4c 29 fe 48 03 b5 78 ff ff ff 48 2b b5 70 ff ff ff e8 ?? ?? ?? ff 48 8d 7d 90 48 8b 77 08 48 8b 95 70 ff ff ff 48 8b 8d 78 ff ff ff e8 ?? ?? ?? ff 4c 39 fb 74 13 48 8d 7d 90 48 8b 77 08 4c 89 fa 48 89 d9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MacOS_Adload_C_2147827625_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MacOS/Adload.C!MTB"
        threat_id = "2147827625"
        type = "TrojanDownloader"
        platform = "MacOS: "
        family = "Adload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 50 08 48 89 08 66 0f ef c0 66 0f 7f 85 80 fc ff ff 48 c7 ?? ?? ?? ff ff 00 00 00 00 48 83 85 e8 fe ff ff 18 ?? ?? 4c 89 e7}  //weight: 1, accuracy: Low
        $x_1_2 = "injector" ascii //weight: 1
        $x_1_3 = "keyenumerator" ascii //weight: 1
        $x_1_4 = ".cxx_destruct" ascii //weight: 1
        $x_1_5 = "_msgSendSuper2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MacOS_Adload_E_2147849297_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MacOS/Adload.E!MTB"
        threat_id = "2147849297"
        type = "TrojanDownloader"
        platform = "MacOS: "
        family = "Adload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.spelling.checker.Agent" ascii //weight: 1
        $x_1_2 = "/tmp/upup2" ascii //weight: 1
        $x_1_3 = "/bin/sh -c  \"/bin/chmod 777" ascii //weight: 1
        $x_1_4 = "-nobrowse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MacOS_Adload_C_2147900252_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MacOS/Adload.C"
        threat_id = "2147900252"
        type = "TrojanDownloader"
        platform = "MacOS: "
        family = "Adload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 44 89 c6 48 89 05 c9 13 00 00 48 8d 3d 1a 0c 00 00 ba 01 00 00 00 e8 36 06 00 00 48 8b 0d b1 13 00 00}  //weight: 2, accuracy: High
        $x_2_2 = {2f 50 4f 53 54 00 [0-32] 65 72 72 6f 72 20 77 68 69 6c 65 20 6d 61 6b 69 6e 67 20 72 65 71 75 65 73 74 3a 20 00 00 00 00 68 74 74 70 3a 2f 2f 6d 2e}  //weight: 2, accuracy: Low
        $x_1_3 = {2e 63 6f 6d 2f 67 2f 75 70 3f 6c 66 3d 00 47 45 54}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MacOS_Adload_G_2147915881_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MacOS/Adload.G!MTB"
        threat_id = "2147915881"
        type = "TrojanDownloader"
        platform = "MacOS: "
        family = "Adload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 d2 90 41 0f b6 1c 16 88 1c 11 48 ff c2 49 39 d1 75 f0 4c 8b 65 90 4c 01 e8 eb 34}  //weight: 1, accuracy: High
        $x_1_2 = {45 31 ff 45 31 e4 e9 88 01 00 00 90 42 0f b6 74 2b ff 48 8b 5d 98 48 8b 45 a0 48 39 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MacOS_Adload_F_2147915945_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MacOS/Adload.F!MTB"
        threat_id = "2147915945"
        type = "TrojanDownloader"
        platform = "MacOS: "
        family = "Adload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 1c 31 88 1c 32 48 ff c6 49 39 f4 75 ?? 4c 8b 65 ?? 4c 8b 4d 98 4c 01 d0 44 89 c9 44 29 e1 89 ca c1 ea 1f 01 ca d1 fa 4c 63 f2 4d 01 e6}  //weight: 1, accuracy: Low
        $x_1_2 = {4c 89 d1 48 83 e1 e0 ?? ?? ?? ?? 48 89 fe 48 c1 ee 05 48 ff c6 89 f2 83 e2 03 48 83 ff 60 0f 83 ?? ?? ?? ?? 31 ff 48 85 d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MacOS_Adload_I_2147917789_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MacOS/Adload.I!MTB"
        threat_id = "2147917789"
        type = "TrojanDownloader"
        platform = "MacOS: "
        family = "Adload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f6 85 20 ff ff ff 01 74 ?? 48 8b bd 30 ff ff ff e8 a0 41 00 00 0f 57 c0 0f 29 85 20 ff ff ff 48 c7 85 30 ff ff ff 00 00 00 00 66 c7 85 20 ff ff ff 02 67 c6 85 22 ff ff ff 00 48 ?? ?? ?? ?? ?? ?? ba 01 00 00 00 4c 89 ee e8 55 41 00 00 f6 85 20 ff ff ff 01}  //weight: 1, accuracy: Low
        $x_1_2 = {55 48 89 e5 41 57 41 56 41 54 53 48 83 ec 60 0f 57 c0 0f 29 45 a0 48 c7 45 b0 00 00 00 00 4c ?? ?? ?? 0f 29 45 c0 48 c7 45 d0 00 00 00 00 66 c7 45 c0 02 64 c6 45 c2 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MacOS_Adload_H_2147918315_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MacOS/Adload.H!MTB"
        threat_id = "2147918315"
        type = "TrojanDownloader"
        platform = "MacOS: "
        family = "Adload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 49 89 d7 ff 15 98 25 00 00 41 89 c6 85 c0 74 ?? 45 89 f4 49 c1 e4 03 31 db 49 8b 3c 1f e8 a8 0e 00 00 48 83 c3 08 49 39 dc}  //weight: 1, accuracy: Low
        $x_1_2 = {41 83 e7 0f 74 ?? 48 89 55 c0 48 89 4d b8 48 89 45 b0 48 8b 1d 42 26 00 00 41 ff cf 41 83 e4 0f 45 31 f6 4b 8b 7c f5 00 48 85 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MacOS_Adload_J_2147918316_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MacOS/Adload.J!MTB"
        threat_id = "2147918316"
        type = "TrojanDownloader"
        platform = "MacOS: "
        family = "Adload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 45 c2 00 48 ?? ?? ?? ba 01 00 00 00 4c 89 f6 e8 aa 09 00 00 f6 45 c0 01 74 ?? 48 8b 7d d0 e8 ad 09 00 00 0f 57 c0 0f 29 45 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 15 45 5e 00 00 41 f6 c7 01 49 0f 44 dd 4c 89 f7 48 8b 35 7b 5f 00 00 48 89 da 48 89 c1 ff 15 27 5e 00 00 48 89 c7 e8 3d 3e 00 00 48 89 c3 f6 85 20 ff ff ff 01 0f ?? ?? ?? ?? ?? f6 85 e8 fe ff ff 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MacOS_Adload_K_2147918317_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MacOS/Adload.K!MTB"
        threat_id = "2147918317"
        type = "TrojanDownloader"
        platform = "MacOS: "
        family = "Adload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff d3 0f 57 c0 0f 29 85 00 ff ff ff 48 c7 85 10 ff ff ff 00 00 00 00 4c ?? ?? ?? ?? ?? ?? 31 db 4c ?? ?? ?? ?? ?? ?? 66 ?? 41 0f b6 07 0f 57 c0 0f 29 85 20 ff ff ff 48 c7 85 30 ff ff ff 00 00 00 00 c6 85 20 ff ff ff 02}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 03 0f 57 c0 0f 29 85 20 ff ff ff 48 c7 85 30 ff ff ff 00 00 00 00 c6 85 20 ff ff ff 02 41 88 45 00 c6 85 22 ff ff ff 00 ba 01 00 00 00 4c 89 ff 4c 89 ee e8 d4 57 00 00 f6 85 20 ff ff ff 01 74 ?? 48 8b bd 30 ff ff ff e8 d1 57 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MacOS_Adload_L_2147918318_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MacOS/Adload.L!MTB"
        threat_id = "2147918318"
        type = "TrojanDownloader"
        platform = "MacOS: "
        family = "Adload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 c6 04 2c 00 4d 8b 7e 10 66 0f ef c0 66 0f 7f 85 a0 fc ff ff 48 c7 85 b0 fc ff ff 00 00 00 00 4c 89 ff e8 52 4b 00 00 48 83 f8 f0 0f ?? ?? ?? ?? ?? 49 89 c5 48 83 f8 17 73 ?? 44 89 e8 44 00 e8 88 85 a0 fc ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {45 31 e4 45 31 ed e9 ?? ?? ?? ?? 0f 1f 84 00 00 00 00 00 4c 39 f1 0f ?? ?? ?? ?? ?? 46 0f b6 7c 37 ff 42 8b 04 37 44 01 c0 41 28 c7 48 8b 9d 08 ff ff ff 48 8b 85 10 ff ff ff 48 39 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MacOS_Adload_M_2147919547_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MacOS/Adload.M!MTB"
        threat_id = "2147919547"
        type = "TrojanDownloader"
        platform = "MacOS: "
        family = "Adload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 48 89 e5 41 56 53 48 81 ec 20 01 00 00 49 89 fe 48 ?? ?? ?? ?? ?? ?? be 20 00 00 00 e8 ?? a3 00 00 83 f8 01 7f ?? 48 ?? ?? ?? ?? ?? ?? 31 f6 4c 89 f2 e8 c8 ab ff ff 48 89 c1}  //weight: 1, accuracy: Low
        $x_1_2 = {48 83 e7 fc 48 8b 5f 08 8b 13 83 e2 03 83 fa 01 74 ?? 48 89 04 f1 48 ff c6 4c 39 c6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MacOS_Adload_Q_2147919548_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MacOS/Adload.Q!MTB"
        threat_id = "2147919548"
        type = "TrojanDownloader"
        platform = "MacOS: "
        family = "Adload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 c9 31 c0 48 29 c8 48 c1 f8 03 48 b9 ab aa aa aa aa aa aa aa 48 0f af c1 66 0f ef c0 48 83 f8 01 0f ?? ?? ?? ?? ?? 66 0f 7f 85 60 fb ff ff 48 c7 85 70 fb ff ff 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {49 8b 57 08 eb ?? 66 2e 0f 1f 84 00 00 00 00 00 48 d1 ea 4c 89 f6 48 89 df e8 68 92 05 00 0f b6 85 00 ff ff ff a8 01 74 ?? 48 8b 8d 08 ff ff ff 48 85 c9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MacOS_Adload_S_2147920005_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MacOS/Adload.S!MTB"
        threat_id = "2147920005"
        type = "TrojanDownloader"
        platform = "MacOS: "
        family = "Adload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4b 8b 7c f5 00 48 85 ff 74 ?? 48 89 de ff 15 a5 21 00 00 49 ff c6 45 39 f4 75 ?? 4c 03 7d c0 48 8b 45 b8 4e ?? ?? ?? ?? 48 8b 45 b0}  //weight: 1, accuracy: Low
        $x_1_2 = {48 03 5d b8 41 bf 01 00 00 00 45 31 f6 49 c1 e6 04 48 8b 45 80 4a 8b 3c 30 48 89 de e8 d2 1c 00 00 85 c0 74 ?? 45 89 fe 41 ff c7 4d 39 ee}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MacOS_Adload_U_2147920006_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MacOS/Adload.U!MTB"
        threat_id = "2147920006"
        type = "TrojanDownloader"
        platform = "MacOS: "
        family = "Adload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 48 89 e5 53 50 48 8b 35 66 24 00 00 48 8b 1d a7 20 00 00 ff d3 48 8b 35 66 24 00 00 48 89 c7 48 89 d8 48 83 c4 08 5b 5d ff e0}  //weight: 1, accuracy: High
        $x_1_2 = {49 89 d7 ff 15 c0 24 00 00 41 89 c6 85 c0 74 ?? 45 89 f4 49 c1 e4 03 31 db 49 8b 3c 1f e8 a8 0e 00 00 48 83 c3 08 49 39 dc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MacOS_Adload_T_2147923768_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MacOS/Adload.T!MTB"
        threat_id = "2147923768"
        type = "TrojanDownloader"
        platform = "MacOS: "
        family = "Adload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 48 89 e5 41 56 53 48 81 ec 30 01 00 00 31 c0 41 b8 20 00 00 00 45 89 c1 41 b8 10 00 00 00 45 89 c2 41 b8 08 00 00 00 45 89 c3 48 8d 5d e8 48 89 bd 78 ff ff ff 48 89 df 48 89 b5 70 ff ff ff 89 c6 48 89 95 68 ff ff ff 4c 89 da 4c 89 95 60 ff ff ff 48 89 8d 58 ff ff ff 4c 89 8d 50 ff ff ff 4c 89 9d 48 ff ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {55 48 89 e5 41 55 48 81 ec e8 00 00 00 48 c7 45 e8 00 00 00 00 48 89 75 f0 48 8b 46 f8 48 8b 48 40 48 83 c1 0f 48 83 e1 f0 49 89 e0 49 29 c8 4c 89 c4 48 89 7d e8 48 8b 48 10 48 89 7d a0 4c 89 c7 48 89 75 98 4c 89 ee}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MacOS_Adload_V_2147929993_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MacOS/Adload.V!MTB"
        threat_id = "2147929993"
        type = "TrojanDownloader"
        platform = "MacOS: "
        family = "Adload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 01 f5 44 89 6d d4 31 d2 49 89 54 24 10 49 89 54 24 08 49 89 14 24 4a 63 0c b1 8a 0c 0f 80 e1 f0 45 31 f6 80 f9 d0 41 0f 94 c6 41 ff c6 44 0f af f0 8b 4b 40 44 89 f0 0f af c1 85 c0 0f 8e f3 00 00 00 48 8d 43 18 48 89 45 98}  //weight: 1, accuracy: High
        $x_1_2 = {89 f2 c1 e2 08 0f b6 74 08 ff 09 d6 48 ff c9 7f ef 49 8b 44 24 08 49 3b 44 24 10 4c 89 fb 73 0d 89 30 48 83 c0 04 49 89 44 24 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MacOS_Adload_P_2147938038_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MacOS/Adload.P!MTB"
        threat_id = "2147938038"
        type = "TrojanDownloader"
        platform = "MacOS: "
        family = "Adload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 89 d6 48 89 c3 48 8d 7d e0 e8 ?? ?? ?? ?? 48 89 df e8 ?? ?? ?? ?? 41 83 fe 02 75 ?? 48 8b 38}  //weight: 1, accuracy: Low
        $x_1_2 = {4d 8b 6e 60 4b 8b 7c 3d f0 e8 ?? ?? ?? ?? 4b 8b 4c 3d f8 4b 8b 54 3d 00 4c 89 e7 48 89 c6 e8 ?? ?? ?? ?? 48 ff c3 49 63 46 68 49 83 c7 18 48 39 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MacOS_Adload_W_2147943310_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MacOS/Adload.W!MTB"
        threat_id = "2147943310"
        type = "TrojanDownloader"
        platform = "MacOS: "
        family = "Adload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 81 fe fe ff ff 7f ba fe ff ff 7f 49 0f 42 d6 bf 02 00 00 00 4c 89 fe e8 80 68 00 00 48 83 f8 ff 74 ca 48 85 c0 74 15 4c 89 f1 48 29 c1 72 28 49 01 c7 49 89 ce 4d 85 f6}  //weight: 1, accuracy: High
        $x_1_2 = {55 48 89 e5 53 50 48 89 fb 48 81 f9 00 04 00 00 b8 00 04 00 00 48 0f 42 c1 bf 02 00 00 00 48 89 d6 89 c2 e8 2e 69 00 00 48 83 f8 ff 74 08 48 89 43 08 31 c0 eb 18}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

