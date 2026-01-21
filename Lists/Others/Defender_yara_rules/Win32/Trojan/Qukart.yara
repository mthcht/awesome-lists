rule Trojan_Win32_Qukart_RPO_2147841275_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qukart.RPO!MTB"
        threat_id = "2147841275"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qukart"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {90 31 30 90 90 90 90 90 90 01 f8 90 90 90 90 e2 ef}  //weight: 1, accuracy: High
        $x_1_2 = {89 c8 90 90 90 90 90 90 f7 f7 90 90 90 91 90 90 90}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qukart_RPP_2147841276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qukart.RPP!MTB"
        threat_id = "2147841276"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qukart"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 08 90 90 90 90 90 83 c0 04 90 90 90 90 90 39 d8 90 90 90 90 75 e9}  //weight: 1, accuracy: High
        $x_1_2 = {90 89 c8 90 90 90 f7 f7 90 91 90 90 90 90 90 90 90 90 58}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qukart_DB_2147846896_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qukart.DB!MTB"
        threat_id = "2147846896"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qukart"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b6 08 8b 95 [0-4] 0f b6 84 15 [0-4] 8b 95 [0-4] 0f b6 94 15 [0-4] 03 c2 25 [0-4] 79 ?? 48 0d 00 ff ff ff 40 0f b6 84 05 [0-4] 33 c8 8b 55 f8 03 95 [0-4] 88 0a e9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qukart_GMA_2147896705_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qukart.GMA!MTB"
        threat_id = "2147896705"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qukart"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ndjvdAWb7" ascii //weight: 1
        $x_1_2 = "wZEBsVzmk" ascii //weight: 1
        $x_1_3 = "PqJwxRfsh" ascii //weight: 1
        $x_1_4 = "tGyjPiEU4" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qukart_GMB_2147896830_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qukart.GMB!MTB"
        threat_id = "2147896830"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qukart"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AExIBzXmZ4" ascii //weight: 1
        $x_1_2 = "uiAnnPhU" ascii //weight: 1
        $x_1_3 = "XbQUlJsV" ascii //weight: 1
        $x_1_4 = "GjYJLdgh" ascii //weight: 1
        $x_1_5 = "LmrJldBf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qukart_GMC_2147896838_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qukart.GMC!MTB"
        threat_id = "2147896838"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qukart"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ehQEyEAc9o" ascii //weight: 1
        $x_1_2 = "GtaRFZjB0" ascii //weight: 1
        $x_1_3 = "eRKveFNZf" ascii //weight: 1
        $x_1_4 = "gDiYHIRd5" ascii //weight: 1
        $x_1_5 = "LInFwtzj" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qukart_ASJ_2147896887_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qukart.ASJ!MTB"
        threat_id = "2147896887"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qukart"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "epvLoQvNFP" ascii //weight: 1
        $x_1_2 = "iLELimpA" ascii //weight: 1
        $x_1_3 = "uWFvLTOM%" ascii //weight: 1
        $x_1_4 = "eDbPVeBL" ascii //weight: 1
        $x_1_5 = "cUqQHauW" ascii //weight: 1
        $x_1_6 = "DuBrDjIe" ascii //weight: 1
        $x_1_7 = "nIfnRtCU" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qukart_ASK_2147897015_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qukart.ASK!MTB"
        threat_id = "2147897015"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qukart"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "UitZIzHa" ascii //weight: 1
        $x_1_2 = "iuEBVjpoC" ascii //weight: 1
        $x_1_3 = "KFEGZCuJ" ascii //weight: 1
        $x_1_4 = "kLsboupow" ascii //weight: 1
        $x_1_5 = "RXVzgwQDx" ascii //weight: 1
        $x_1_6 = "VHsOPNbn" ascii //weight: 1
        $x_1_7 = "vSpTDfbtNm" ascii //weight: 1
        $x_1_8 = "LdKDBKia" ascii //weight: 1
        $x_1_9 = "CFsoBMYp" ascii //weight: 1
        $x_1_10 = "MEgNhMdS" ascii //weight: 1
        $x_1_11 = "uPjkAcsh" ascii //weight: 1
        $x_1_12 = "FtPzwOSy" ascii //weight: 1
        $x_1_13 = "GCoWhYfg" ascii //weight: 1
        $x_1_14 = "THxrEhIa" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Trojan_Win32_Qukart_ASL_2147897263_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qukart.ASL!MTB"
        threat_id = "2147897263"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qukart"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "coHULkZi" ascii //weight: 1
        $x_1_2 = "eKzdrgWl" ascii //weight: 1
        $x_1_3 = "nbdDpnwk" ascii //weight: 1
        $x_1_4 = "BsmTznkN" ascii //weight: 1
        $x_1_5 = "hyOIZTvy" ascii //weight: 1
        $x_1_6 = "YlnwLSIsA" ascii //weight: 1
        $x_1_7 = "SRrrhMls" ascii //weight: 1
        $x_1_8 = "OEmMmgvu" ascii //weight: 1
        $x_1_9 = "uJclxPAg" ascii //weight: 1
        $x_1_10 = "vsxQGyKO" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qukart_GMD_2147897372_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qukart.GMD!MTB"
        threat_id = "2147897372"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qukart"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "xHHuJPqD" ascii //weight: 1
        $x_1_2 = "KBeWjEpb@" ascii //weight: 1
        $x_1_3 = "uRTRyPSF" ascii //weight: 1
        $x_1_4 = "pfNqKtqe" ascii //weight: 1
        $x_1_5 = "FKneEWkl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qukart_ASM_2147897399_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qukart.ASM!MTB"
        threat_id = "2147897399"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qukart"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "lLojEYtY+" ascii //weight: 1
        $x_1_2 = "pkcPztnX" ascii //weight: 1
        $x_1_3 = "kvcLdmQj" ascii //weight: 1
        $x_1_4 = "DERuyYqLb" ascii //weight: 1
        $x_1_5 = "hyiENdFm" ascii //weight: 1
        $x_1_6 = "dQUsFFCi" ascii //weight: 1
        $x_1_7 = "DXEHHZdy" ascii //weight: 1
        $x_1_8 = "NyfIkRIF" ascii //weight: 1
        $x_1_9 = "xlnvmMde" ascii //weight: 1
        $x_1_10 = "wVihoHYqr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qukart_ASN_2147897421_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qukart.ASN!MTB"
        threat_id = "2147897421"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qukart"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bjGmyAIq" ascii //weight: 1
        $x_1_2 = "RAvbowatK" ascii //weight: 1
        $x_1_3 = "WnEMmKDx" ascii //weight: 1
        $x_1_4 = "niLpUStw" ascii //weight: 1
        $x_1_5 = "FcENWTaQ2" ascii //weight: 1
        $x_1_6 = "ZicfuotE" ascii //weight: 1
        $x_1_7 = "lpsGXWjt" ascii //weight: 1
        $x_1_8 = "VbzUJACU" ascii //weight: 1
        $x_1_9 = "gDKJnkdi" ascii //weight: 1
        $x_1_10 = "GFbiYiDF" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qukart_ASO_2147897605_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qukart.ASO!MTB"
        threat_id = "2147897605"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qukart"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 7d 08 ba d3 4d 62 10 51 89 c1 f7 ea c1 fa 07 c1 f9 1f 29 ca 89 d0 59 89 c2 83 c2 61 88 14 37 46 39 de 7c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qukart_RE_2147897789_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qukart.RE!MTB"
        threat_id = "2147897789"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qukart"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5d 5f 5e 5b 89 ec 5d c3 fc 55 89 e5 83 ec 08 53 56 57 55 8b 5d 0c 8b 45 08 a3 8c d0 42 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qukart_RF_2147897790_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qukart.RF!MTB"
        threat_id = "2147897790"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qukart"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3d ff ff 00 00 74 05 31 c0 40 eb 13 81 f7 17 01 00 00 83 c6 11}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qukart_ASP_2147898885_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qukart.ASP!MTB"
        threat_id = "2147898885"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qukart"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2d 44 90 82 7e 91 2b 1b 48 2f 2c 4b 11 e3 1a 13 21 e3 7c}  //weight: 5, accuracy: High
        $x_5_2 = {55 89 e5 81 ec f0 01 00 00 53 56 57 bb b3 17 c6 3b 89 d8 01 d8 89 c3 83 a5}  //weight: 5, accuracy: High
        $x_5_3 = {1d 8b 00 e3 84 b6 3c 33 4b 8b 8b d6 3d 5b 42 e3 fa 2e 8d de 35 [0-4] b6 34 33 4b 8b 59 bc 57 74 54 6c 0d d6 5e 68 54}  //weight: 5, accuracy: Low
        $x_5_4 = {b8 a2 ab 0a dc 01 68 0a 89 88 [0-4] fc 81 81 [0-4] 73 cc 83 2c 30 5b 83 1a 82 [0-4] 54 7f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Qukart_ASQ_2147899043_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qukart.ASQ!MTB"
        threat_id = "2147899043"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qukart"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b fe bc 8a d8 57 14 8a 99 6d 94 37 ac 95 4e b9 ac 7d c7 b1 a4 82 71 65 7c 3f 44 9d 48 b6 44 75 2f b9 40 cd ad 7d 44 75}  //weight: 5, accuracy: High
        $x_5_2 = {3d 27 33 8b b2 52 b7 8c b5 04 48 83 31 21 44 f5 b2 d0 c7 87 31 d8 35 d5 64 21 23 93 ba e9 a4 08 31 27 48 20 01 7c}  //weight: 5, accuracy: High
        $x_5_3 = {ad 37 2a e8 b1 1b 81 13 e5 90 f4 9c 9d 33 31 17 cd 37 7e 79 64 27 7c}  //weight: 5, accuracy: High
        $x_5_4 = {1b 52 53 e6 61 68 c5 18 9e 38 2d f1 98 5a ad 19 1d fc 8d 90 1b 5c 53 e6 61 31 6d 6d 82 50 ad 18}  //weight: 5, accuracy: High
        $x_5_5 = {28 11 c9 d1 ab 63 4a d9 59 31 1f 20 4f 77 c1 e8 c8 ec 4a 26 24 c4 7a}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Qukart_GAD_2147899085_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qukart.GAD!MTB"
        threat_id = "2147899085"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qukart"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 f8 f7 e7 89 45 fc 89 c7 8b 45 0c 3d 00 01 00 00 0f 85 ?? ?? ?? ?? 89 f8 31 f8 89 c7 83 7d 10 09 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qukart_GAF_2147899420_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qukart.GAF!MTB"
        threat_id = "2147899420"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qukart"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 f8 29 f0 8b 55 08 8a 14 3a 88 94 05 ?? ?? ?? ?? 47 39 df 7c}  //weight: 10, accuracy: Low
        $x_10_2 = {6a 00 6a 00 e8 ?? ?? ?? ?? 89 f0 f7 e6 89 85 ?? ?? ?? ?? 89 c6 8d 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qukart_ASR_2147899602_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qukart.ASR!MTB"
        threat_id = "2147899602"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qukart"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {89 e5 51 50 56 57 bf 39 4a b9 09 81 c7 9e 1d 00 00 8d 45 f8 50 8d 45 fc 50 6a 00 68 3f 00 0f 00 6a 00 6a 00 6a 00 ff 75 0c ff 75 08 e8 ?? ?? 00 00 89 c6 81 ef cb 52 00 00 09 f6 74}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qukart_ASCA_2147899833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qukart.ASCA!MTB"
        threat_id = "2147899833"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qukart"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {89 e5 51 50 56 57 bf 6f 26 9e 39 89 f8 01 f8 89 c7 8d 45 fc 50 68 19 00 02 00 6a 00 ff 75 0c ff 75 08 e8}  //weight: 2, accuracy: High
        $x_2_2 = {89 e5 51 50 56 57 bf 5e 3a fc 78 89 f8 31 f8 89 c7 8d 45 f8 50 8d 45 fc 50 6a 00 68 3f 00 0f 00 6a 00 6a 00 6a 00 ff 75 0c ff 75 08 e8}  //weight: 2, accuracy: High
        $x_2_3 = {53 56 57 8b 75 0c 8b 5d 10 c7 85 fc ff fe ff b7 4b 62 37 8b 85 fc ff fe ff 89 c2 31 c2 89 95}  //weight: 2, accuracy: High
        $x_2_4 = {e5 83 ec 0c 53 56 57 8b 75 0c bb fb 52 a9 66 89 d8 31 d8 89 c3 ff 05}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Qukart_ASCB_2147900155_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qukart.ASCB!MTB"
        threat_id = "2147900155"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qukart"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {55 89 e5 83 ec 0c 56 57 bf af 19 aa 46 89 f8 01 f8 89 c7 8d 45 f8 50 8d 45 fc 50 6a 00 68 3f 00 0f 00 6a 00 6a 00 6a 00 ff 75 0c ff 75 08 e8}  //weight: 2, accuracy: High
        $x_2_2 = {55 89 e5 51 56 57 bf 48 3b a2 7f 81 ef dc 4b 00 00 8d 45 fc 50}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qukart_SPXX_2147900411_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qukart.SPXX!MTB"
        threat_id = "2147900411"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qukart"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {89 da 21 d2 81 e0 ff 00 00 00 29 cb 21 c9 81 c3 34 74 06 72 31 06 42 f7 d2 46 b9 2e 19 2a 9e 81 c2 09 75 f6 08 21 cb 47 21 d1 81 ea 85 77 6c ab 81 fe}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qukart_GZA_2147901688_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qukart.GZA!MTB"
        threat_id = "2147901688"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qukart"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 e5 83 ec ?? 56 57 bf ?? ?? ?? ?? 89 f8 f7 e7 89 45 ?? 89 c7 31 f8 89 c7 8d 45 ?? 50 8d 45 ?? 50 6a 00 68 ?? ?? ?? ?? 6a 00 6a 00 6a 00 ff 75 ?? ff 75 ?? e8 ?? ?? ?? ?? 89 c6 09 f6}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qukart_GZZ_2147902168_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qukart.GZZ!MTB"
        threat_id = "2147902168"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qukart"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 4b 4a 6b 45 6b 76 4d 71}  //weight: 10, accuracy: High
        $x_10_2 = {42 65 4a 4b 48 7a ?? 75 ?? 35 ?? ?? ?? ?? 03 00 00 36}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qukart_GZE_2147902293_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qukart.GZE!MTB"
        threat_id = "2147902293"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qukart"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c0 2e 64 61 ?? ?? 00 00 00 f8 33 00 00 00 c0 02 00 f8 33 00}  //weight: 10, accuracy: Low
        $x_10_2 = {00 69 45 49 6a 72 6b 42 73 67 82 00 00 00 10}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qukart_GZF_2147902366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qukart.GZF!MTB"
        threat_id = "2147902366"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qukart"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {00 d0 31 00 00 00 b0 02 00 d0 31 00}  //weight: 10, accuracy: High
        $x_10_2 = {00 49 69 63 4d 57 4e 59 71 93 19 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qukart_GZF_2147902366_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qukart.GZF!MTB"
        threat_id = "2147902366"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qukart"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {68 02 85 8b 79 6a a0 8b cf ?? ?? 65 56 81 74 04 ?? 81 68 45 52 ?? ?? 52 c5 a8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Qukart_AQU_2147961412_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qukart.AQU!MTB"
        threat_id = "2147961412"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qukart"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c3 29 d8 89 c3 29 d8 89 c3 29 d8 89 c3 68 04 01 00 00 8d 85 fc fe ff ff 50 e8 ?? ?? ?? ?? 89 d8 f7 e3 89 85 d8 fe ff ff 89 c3 81 f3 10 09 00 00 89 d8 31 d8 89 c3 8d 85 ec fe ff ff 50 8d 85 fc fe ff ff 50 68 a0 30 00 10 8d 85 fc fe ff ff 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

