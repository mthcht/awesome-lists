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

rule Trojan_Win32_SalatStealer_CL_2147960482_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SalatStealer.CL!MTB"
        threat_id = "2147960482"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SalatStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "main.DecryptGecko" ascii //weight: 2
        $x_2_2 = "main.decryptAPPB" ascii //weight: 2
        $x_2_3 = "main.enablePrivilege" ascii //weight: 2
        $x_2_4 = "main.findLsassProcess" ascii //weight: 2
        $x_2_5 = "main.getSystemToken" ascii //weight: 2
        $x_2_6 = "main.selfDelete" ascii //weight: 2
        $x_2_7 = "main.GetAppBoundKey" ascii //weight: 2
        $x_2_8 = "main.decryptDataEdge" ascii //weight: 2
        $x_2_9 = "main.GetChromiumMasterKeys" ascii //weight: 2
        $x_2_10 = "main.isAdmin" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SalatStealer_GTV_2147961112_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SalatStealer.GTV!MTB"
        threat_id = "2147961112"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SalatStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GetKeyboardStateGetClipboardDataGetLastInput" ascii //weight: 1
        $x_1_2 = "Electrum\\wallet" ascii //weight: 1
        $x_1_3 = "processBrowsers\\Logins_$appdata\\discordread" ascii //weight: 1
        $x_1_4 = "cookies.sqliteloginusers.vdfpassword" ascii //weight: 1
        $x_1_5 = "TelegramDesktopNetwork\\Cookies" ascii //weight: 1
        $x_1_6 = "httpbibawinv.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SalatStealer_YBG_2147961680_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SalatStealer.YBG!MTB"
        threat_id = "2147961680"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SalatStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sleep patch detected" ascii //weight: 1
        $x_1_2 = "VM detected" ascii //weight: 1
        $x_1_3 = "Debugger detected" ascii //weight: 1
        $x_1_4 = "Decryption SUCCESS" ascii //weight: 1
        $x_4_5 = " < 2GB)! Ex" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SalatStealer_MK_2147964610_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SalatStealer.MK!MTB"
        threat_id = "2147964610"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SalatStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "Low"
    strings:
        $x_35_1 = {f7 e1 89 06 89 d8 89 56 08 f7 e1 31 c9 89 c3 8b 46 04 03 5e 08 11 ca 89 56 08 31 d2 f7 f7 81 7e ?? ?? ?? ?? ?? 8b 16 8b 7e 08 0f 44 d1 0f 44 c1 0f 44 f9 0f 44 d9 01 d0 11 cb 11 cf 0f 92 06 6a ?? 5a 39 c2 b8 00 00 00 00 19 d8 b8 00 00 00 00 19 f8 0f b6 06 19 c1}  //weight: 35, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SalatStealer_MKA_2147965217_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SalatStealer.MKA!MTB"
        threat_id = "2147965217"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SalatStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "Low"
    strings:
        $x_35_1 = {0f 28 ca 0f 57 c8 0f 11 49 ?? 0f 28 ca 0f 10 41 ?? 0f 57 c2 0f 11 41 ?? 0f 10 41 ?? 0f 57 c2 0f 11 41 ?? 0f 10 41 ?? 0f 57 c8 0f 11 49 ?? 3b 85 dc fc ff ff}  //weight: 35, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SalatStealer_GXH_2147966502_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SalatStealer.GXH!MTB"
        threat_id = "2147966502"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SalatStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f af fa f7 e2 01 ca 8b 4c 24 ?? 01 fa 8b 7c 24 ?? 29 d8 89 c6 89 44 24 ?? 19 fa 0f a4 d6 ?? 89 54 24 ?? 0f a4 c2 ?? 8b 44 24 ?? 01 c2 11 ce 31 d3 ba ?? ?? ?? ?? 31 f7 01 d8 89 5c 24 ?? 8b 5c 24 ?? 89 c6}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SalatStealer_BAA_2147966718_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SalatStealer.BAA!MTB"
        threat_id = "2147966718"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SalatStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 d9 89 d8 c1 e9 18 c1 e8 0c 31 c8 8b 4e ?? 01 f9 89 4e ?? 31 8e ?? ?? ?? ?? 8b 4e ?? 32 81}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SalatStealer_SS_2147967170_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SalatStealer.SS!MTB"
        threat_id = "2147967170"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SalatStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b7 8c 04 08 08 00 00 66 89 4c 04 08 83 c0 02 66 85 c9 75 eb 8d 54 24 08 52 ff 15 ac 81 ?? 00 68 b0 97 ?? 00 8d 44 24 0c 50 ff 15 b0 81 ?? 00 6a 00 8d 4c 24 0c 51 8d 94 24 10 08 00 00 52 ff 15 10 80 ?? 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SalatStealer_MKZ_2147968501_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SalatStealer.MKZ!MTB"
        threat_id = "2147968501"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SalatStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {89 c1 80 c1 bc 30 4c 06 68 40 eb f0 8d be ?? ?? ?? ?? 8d 56 49 89 f9 6a 1f e8}  //weight: 3, accuracy: Low
        $x_2_2 = {89 c1 80 c1 15 30 4c 04 14 40 eb f0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SalatStealer_GKK_2147971040_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SalatStealer.GKK!MTB"
        threat_id = "2147971040"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SalatStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 ec 8a 5c 18 ff 0f b6 c1 8b 4d ?? 32 9c 05 ?? ?? ?? ?? c0 c3 02 3b 39 ?? ?? 51 e8 ?? ?? ?? ?? 8b 4d ?? 83 c4 ?? 8b 41 ?? 8b 55 ?? 88 1c 38 8b 45 ?? 89 f3 47 43}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SalatStealer_DD_2147971388_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SalatStealer.DD!MTB"
        threat_id = "2147971388"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SalatStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 c6 f2 0f 11 00 f2 0f 11 48 08 f2 0f 10 0d 20 9b 43 00 f2 0f 11 50 10 f2 0f 10 15 30 9b 43 00 f2 0f 11 48 18 f2 0f 10 0d 40 9b 43 00 f2 0f 11 50 20 f2 0f 10 15 50 9b 43 00 f2 0f 11 48 28 f2 0f 10 0d 60 9b 43 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SalatStealer_KBX_2147974572_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SalatStealer.KBX!MTB"
        threat_id = "2147974572"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SalatStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "loader.startloader.apis.ok" ascii //weight: 1
        $x_1_2 = "state.payload" ascii //weight: 1
        $x_1_3 = "state.payload.decrypted" ascii //weight: 1
        $x_1_4 = "state.payload.encrypted" ascii //weight: 1
        $x_1_5 = "state.junk" ascii //weight: 1
        $x_1_6 = "state.exec.start" ascii //weight: 1
        $x_1_7 = "exec.decoy.start" ascii //weight: 1
        $x_1_8 = "exec.decoy.done" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SalatStealer_MMX_2147974662_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SalatStealer.MMX!MTB"
        threat_id = "2147974662"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SalatStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c6 8d 45 f3 c6 45 f3 01 89 45 e8 8d 45 e8 68}  //weight: 1, accuracy: High
        $x_1_2 = {50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 73 00 76 00 63 00 5f 00 [0-16] 2e 00 6c 00 6f 00 67 00}  //weight: 1, accuracy: Low
        $x_1_3 = "state.payload.decrypted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SalatStealer_BAB_2147975282_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SalatStealer.BAB!MTB"
        threat_id = "2147975282"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SalatStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CookiesNamed" ascii //weight: 1
        $x_1_2 = "writeKeyLog" ascii //weight: 1
        $x_1_3 = "net/http.(*socksDialer).connect.deferwrap1" ascii //weight: 1
        $x_1_4 = "main.PayloadContainer" ascii //weight: 1
        $x_1_5 = "SetCookies" ascii //weight: 1
        $x_1_6 = "stub/utils.Decode" ascii //weight: 1
        $x_1_7 = "decryptionKey" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SalatStealer_DA_2147975368_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SalatStealer.DA!MTB"
        threat_id = "2147975368"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SalatStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {05 00 56 97 05 a0 8f 98 05 70 55 97 05 a0 55 97 05 10 58 97 05 90 66 99 05 50 6a 99 05 c0 6a 99 05 30 6b 99 05 a0 6b 99 05 f0 6b 99 05 30 6c 99 05 70 6c 99 05 b0 6c 99 05 f0 6c 99 05 30 6d 99 05 d0 66 99 05 70 6d 99 05 e0 6e 99 05 20 6f 99 05 60 6f 99 05 d0 70 99 05 10 71 99 05 50 71 99 05 90}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SalatStealer_DB_2147975625_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SalatStealer.DB!MTB"
        threat_id = "2147975625"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SalatStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {a0 00 f1 02 02 86 04 ba 06 26 0a 95 02 0c a5 02 10 65 02 0c a0 12 26 14 ad 02 1a f6 1e 96 20 38 22 94 26 09 04 2a 38 2c 39 03 2a 09 02 2e c1 02 30 98 32 2c 34 25 03 3a be 18 70 3a d0 3e 96 40 38 44 f1 02 46 11 03 4a b2 4c 3a 4e 90 52 09 04 56 68 58 41 03 5a aa 58 31 02 5c e9 02 3a 4c 5e a5 02 3a 79 02 30 75 03 60 d4 30 b6 62 50 30 85 02 64 19 02 30 4d 06 0c 7d 02 00 6c 3c 0c 32 0c 04 26 0e 2e 10 0c 12 26 1c 88 2c 32 1e 2e 60 8e 58 32 62 2c 64 2e 5a 26 4a 2a 48 0c 3e 19 2d 0a 00 1c 01 63 00 0d f0 0b e0 09 d0 07 c0 05 70 04 60}  //weight: 1, accuracy: High
        $x_1_2 = {0d 4d 7a 39 02 00 1c 02 c2 04 5a 06 11 03 04 88 08 9a 0a 6e 08 8c 0c 94 0e 2c 10 b6 14 6d 04 18 4c 1a c8 14 3a 1a 4d 02 18 25 02 1c 69 02 08 6c 1e 6c 20 66 22 3e 24 fc 28 88 2c fa 2e c2 32 ad 02 34 74 32 ac 36 ac 38 2c 3a b0 3e 55 04 42 4e 44 cc 3e 3a 44 4d 02 42 25 02 46 b9 02 2c a4 48 2c 4a 30 4c 75 05 54 2a 56 81 03 50 46 56 70 54 25 02 58 91 04 00 60 04 34 0a 0c 0c 92 1a 34 2c 28 34 0c 36 92 44 34 48 78 56 34 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

