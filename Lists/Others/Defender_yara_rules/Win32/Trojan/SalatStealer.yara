rule Trojan_Win32_SalatStealer_KAT_2147946544_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SalatStealer.KAT!MTB"
        threat_id = "2147946544"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SalatStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.decryptData" ascii //weight: 1
        $x_1_2 = "findLsassProcess" ascii //weight: 1
        $x_1_3 = "shellCommand" ascii //weight: 1
        $x_1_4 = "sendScreen" ascii //weight: 1
        $x_1_5 = "runKeylogger" ascii //weight: 1
        $x_1_6 = "salat/main" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SalatStealer_NV_2147953702_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SalatStealer.NV!MTB"
        threat_id = "2147953702"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SalatStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {21 d3 09 eb 84 db 75 06 31 d2 31 db eb 14 e8 16 6f 06 00 8b 04 24 8b 4c 24 04 89 ca 89 c3 8b 44 24 3c 89 5c 24 18 89 54 24 1c 8d 48 30}  //weight: 2, accuracy: High
        $x_1_2 = {ff 74 20 e8 7c 7a 06 00 89 0f 8b 58 08 89 5f 04 89 47 08 8b 59 04 89 5f 0c 8b 5e 2c 89 5f 10 8b 5c 24 18 89 48 08 89 41 04 89 46 2c eb 30 8b 0d 60 4a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SalatStealer_ASE_2147954201_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SalatStealer.ASE!MTB"
        threat_id = "2147954201"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SalatStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 3c 3a 31 ef 8b 6c 24 48 97 88 04 2b 97 8d 45 01 89 f2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SalatStealer_NS_2147954535_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SalatStealer.NS!MTB"
        threat_id = "2147954535"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SalatStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 07 09 c0 74 3c 8b 5f 04 8d 84 30 00 70 b8 00 01 f3 50 83 c7 08 ff 96 28 70 b8 00}  //weight: 2, accuracy: High
        $x_1_2 = {ff 96 2c 70 b8 00 83 c7 04 8d 5e fc 31 c0 8a 07 47 09 c0}  //weight: 1, accuracy: High
        $x_1_3 = {8a 07 47 08 c0 74 dc 89 f9 57 48 f2 ae 55 ff 96 30 90 b8 00 09 c0 74 07 89 03 83 c3 04 eb e1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_SalatStealer_NB_2147954601_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SalatStealer.NB!MTB"
        threat_id = "2147954601"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SalatStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 5f 04 8d 84 30 00 e0 b7 00 01 f3 50 83 c7 08 ff 96 28 e0 b7 00 95 8a 07 47}  //weight: 2, accuracy: High
        $x_1_2 = {ff 96 30 e0 b7 00 09 c0 74 07 89 03 83 c3 04 eb e1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SalatStealer_NC_2147954718_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SalatStealer.NC!MTB"
        threat_id = "2147954718"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SalatStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 07 09 c0 74 3c 8b 5f 04 8d 84 30 00 00 b8 00 01 f3}  //weight: 2, accuracy: High
        $x_1_2 = {ff 96 2c 00 b8 00 83 c7 04 8d 5e fc 31 c0 8a 07 47 09 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SalatStealer_EI_2147956951_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SalatStealer.EI!MTB"
        threat_id = "2147956951"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SalatStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 3d 68 6e f9 00 0f b6 3c 3a 31 ef 8b 6c 24 48 97 88 04 2b 97 8d 45 01 89 f2 39 c2 7e 1d 8b 0d 6c 6e f9 00 0f b6 2c 18 85 c9 74 26 89 44 24 48 89 d6 99 f7 f9 39 d1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SalatStealer_KK_2147957116_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SalatStealer.KK!MTB"
        threat_id = "2147957116"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SalatStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {60 be 15 30 ca 00 8d be eb df 75 ff 57 89 e5 8d}  //weight: 20, accuracy: High
        $x_10_2 = {68 d0 bf 00 4a d0 bf 00}  //weight: 10, accuracy: High
        $x_5_3 = {3c d0 bf 00 28 d0 bf}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SalatStealer_SMX_2147957148_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SalatStealer.SMX!MTB"
        threat_id = "2147957148"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SalatStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "33"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "Go build" ascii //weight: 20
        $x_10_2 = "ArmoryExodusGuardaBitappCoin98FewchaFinnieIconexKaikasOxygenPontemSaturnSolletWombatXMR" ascii //weight: 10
        $x_10_3 = "ChromeChedotKometaFenrirCoowonLiebaoDragonCocCocYandex" ascii //weight: 10
        $x_1_4 = "GetClipboard" ascii //weight: 1
        $x_1_5 = "GetKeyboardState" ascii //weight: 1
        $x_1_6 = "taskkill" ascii //weight: 1
        $x_1_7 = "Browsers\\Cookies" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_10_*) and 3 of ($x_1_*))) or
            ((1 of ($x_20_*) and 2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_SalatStealer_ASAL_2147957524_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SalatStealer.ASAL!MTB"
        threat_id = "2147957524"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SalatStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {95 88 44 0a 01 95 40 83 c2 02 83 f8 31 7d 3b 0f b6 9c 04 87 00 00 00 89 dd c0 eb 04 0f b6 db 8d 35 2d 4f 97 00 0f b6 1c 1e 83 fa 62 0f 83}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SalatStealer_NQ_2147958236_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SalatStealer.NQ!MTB"
        threat_id = "2147958236"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SalatStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0c eb c1 5d f0 87 37 a1 ?? ?? ?? ?? 1f 4f 4b e5 b4 96}  //weight: 2, accuracy: Low
        $x_1_2 = {b3 46 4d 4a 3e 87 39 0f 9c 57 da 7e f7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SalatStealer_ASSE_2147958394_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SalatStealer.ASSE!MTB"
        threat_id = "2147958394"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SalatStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 44 24 2c 8b 44 24 28 89 44 24 30 8d 05 f9 5f 98 00 89 04 24 c7 44 24 04 ?? ?? ?? ?? 8d 44 24 2c 89 44 24 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SalatStealer_NE_2147958658_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SalatStealer.NE!MTB"
        threat_id = "2147958658"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SalatStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 07 09 c0 74 3c 8b 5f 04 8d 84 30 00 b0 c3 00 01 f3 50 83 c7 08 ff 96 28 b0 c3 00 95 8a 07 47 08 c0 74 dc}  //weight: 1, accuracy: High
        $x_1_2 = "Go build ID" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SalatStealer_NRR_2147958664_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SalatStealer.NRR!MTB"
        threat_id = "2147958664"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SalatStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {80 eb e8 01 f0 89 07 83 c7 05 88 d8 e2 d9 8d be 00 ?? c1 00 8b 07 09 c0}  //weight: 3, accuracy: Low
        $x_3_2 = {8a 07 47 08 c0 74 dc 89 f9 57 48 f2 ae 55 ff 96 30 ?? c3 00 09 c0 74 07 89 03 83 c3 04 eb e1}  //weight: 3, accuracy: Low
        $x_2_3 = "Go build ID" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

