rule Trojan_Win64_Vidar_PC_2147887433_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Vidar.PC!MTB"
        threat_id = "2147887433"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b f7 d3 ee 03 c7 89 45 e0 c7 05 84 39 92 01 ee 3d ea f4 03 75 d0 8b 45 e0 31 45 f8 33 75 f8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Vidar_UL_2147892926_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Vidar.UL!MTB"
        threat_id = "2147892926"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b d6 d3 ea 8d 04 37 89 45 e8 c7 05 a8 a6 61 00 ee 3d ea f4 03 55 dc 8b 45 e8 31 45 fc 33 55 fc 81 3d 10 b1 61 00 13 02 00 00 89 55 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Vidar_AB_2147893043_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Vidar.AB!MTB"
        threat_id = "2147893043"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b d0 8b c8 c1 ea 05 03 54 24 28 c1 e1 04 03 4c 24 2c 03 c7 33 d1 33 d0 2b f2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Vidar_PSD_2147899275_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Vidar.PSD!MTB"
        threat_id = "2147899275"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {4c 89 f0 48 89 81 b8 ?? ?? ?? 48 8b 44 24 30 48 89 81 a8 ?? ?? ?? 48 8d 44 24 38 48 89 81 b0 ?? ?? ?? b8 01 ?? ?? ?? eb 02 31 c0 48 89 4c 24 20 88 44 24 1f 48 8b 15 b8 ?? ?? ?? 48 89 14 24 48 8d 91 78 ?? ?? ?? 48 89 54 24 08 e8 83 e5 02 00 45 0f 57 ff}  //weight: 5, accuracy: Low
        $x_1_2 = "MapKeys" ascii //weight: 1
        $x_1_3 = "runtime.persistentalloc" ascii //weight: 1
        $x_1_4 = "CoreDump" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Vidar_CCFX_2147899887_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Vidar.CCFX!MTB"
        threat_id = "2147899887"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 8b 49 64 41 03 89 ?? ?? ?? ?? 41 8b 91 ?? ?? ?? ?? 81 f1 ?? ?? ?? ?? 0f af c1 81 c2 ?? ?? ?? ?? 41 89 41 0c 41 03 51 40 41 8b 81 ?? ?? ?? ?? 0f af c2 41 89 81 ?? ?? ?? ?? 49 81 fa}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Vidar_AVI_2147937730_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Vidar.AVI!MTB"
        threat_id = "2147937730"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 ff c2 45 69 c0 ?? ?? ?? ?? 8b c8 c1 e9 18 33 c8 69 c9 ?? ?? ?? ?? 44 33 c1 48 3b d3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Vidar_SLAE_2147941890_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Vidar.SLAE!MTB"
        threat_id = "2147941890"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 05 ee 9b 03 00 8d 48 ff 0f af c8 f6 c1 01 b8 58 b2 7a ac 41 0f 44 c5 83 3d d9 9b 03 00 0a 41 0f 4c c5 3d 8d 96 34 06}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Vidar_BOZ_2147944027_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Vidar.BOZ!MTB"
        threat_id = "2147944027"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {01 c1 0f b6 c1 48 8b 4d b0 8a 04 01 48 63 4d ?? 48 8b 55 88 30 04 0a 44 8b 5d ?? 41 83 c3 01 b8 c1 04 f3 84 44 8b 4d a0 4c 8b 45 80 44 8b 75 ?? 44 8b 6d 94 8b 5d 98 3d 12 dd 65 dd 0f 8f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Vidar_ARA_2147952226_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Vidar.ARA!MTB"
        threat_id = "2147952226"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {41 0f b6 08 ff c2 83 e1 0f 4a 0f be 84 11 e0 54 01 00 42 8a 8c 11 f0 54 01 00 4c 2b c0 41 8b 40 fc d3 e8 4c 89 47 08 89 47 18 41 0f b6 08 83 e1 0f}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Vidar_ZPB_2147952660_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Vidar.ZPB!MTB"
        threat_id = "2147952660"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = "https://t.me/l07tp" ascii //weight: 4
        $x_4_2 = "https://steamcommunity.com/profiles/76561199869630181" ascii //weight: 4
        $x_2_3 = {68 04 01 00 00 8d bd ?? ?? ?? ?? 57 6a 00 ff 15 ?? ?? ?? ?? 85 c0 74 07 57 ff 15 ?? ?? ?? ?? 83 bd ?? ?? ?? ?? 10 8d 85 ?? ?? ?? ?? 72 06 8b 85 ?? ?? ?? ?? 50 6a 00 68 03 00 1f 00 ff 15 ?? ?? ?? ?? 85 c0 74 08 50 ff d3 4e 75 b4}  //weight: 2, accuracy: Low
        $x_2_4 = "\\\\Monero\\\\wallet" ascii //weight: 2
        $x_2_5 = "\\\\Discord\\\\token" ascii //weight: 2
        $x_1_6 = "[Hardware]" ascii //weight: 1
        $x_1_7 = "Soft: FileZilla" ascii //weight: 1
        $x_1_8 = "Soft: WinSCP" ascii //weight: 1
        $x_1_9 = "Password:" ascii //weight: 1
        $x_1_10 = "MachineID:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Vidar_LMO_2147953645_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Vidar.LMO!MTB"
        threat_id = "2147953645"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {5f a9 90 8c 99 9a 86 01 41 e9 f1 ab a3 5e}  //weight: 10, accuracy: High
        $x_5_2 = {0c 0f 57 c0 14 53 7e 08 37 89 0b}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Vidar_AHB_2147954705_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Vidar.AHB!MTB"
        threat_id = "2147954705"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {48 89 84 24 18 01 00 00 48 89 c6 48 83 e0 fc 48 89 f7 48 29 c6 48 83 fe ?? 7f}  //weight: 30, accuracy: Low
        $x_20_2 = {48 89 d6 48 f7 eb 48 8d 3c 13 48 c1 ff ?? 48 29 cf 48 8d 3c bf 48 29 fb 48 39 de 7c ab}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Vidar_YAF_2147954857_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Vidar.YAF!MTB"
        threat_id = "2147954857"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "222"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "https://telegram.me/" ascii //weight: 10
        $x_10_2 = "https://steamcommunity.com" ascii //weight: 10
        $x_10_3 = "*.address.txt" ascii //weight: 10
        $x_10_4 = "passwords.txt" ascii //weight: 10
        $x_10_5 = "Screenshot" ascii //weight: 10
        $x_10_6 = "*.keys" ascii //weight: 10
        $x_10_7 = "Wallets" ascii //weight: 10
        $x_10_8 = "chromium_plugins" ascii //weight: 10
        $x_10_9 = "key received successfully" ascii //weight: 10
        $x_10_10 = "Payload loaded" ascii //weight: 10
        $x_10_11 = "telegram_files" ascii //weight: 10
        $x_10_12 = "discord_files" ascii //weight: 10
        $x_10_13 = "\\Network\\Cookies" ascii //weight: 10
        $x_10_14 = "Crypto Reader" ascii //weight: 10
        $x_10_15 = "File Grabber" ascii //weight: 10
        $x_10_16 = "screenshot.jpg" ascii //weight: 10
        $x_10_17 = "formhistory.db" ascii //weight: 10
        $x_10_18 = "_cookies.db" ascii //weight: 10
        $x_10_19 = "passwords.db" ascii //weight: 10
        $x_10_20 = "webdata.db" ascii //weight: 10
        $x_10_21 = "Login Data" ascii //weight: 10
        $x_10_22 = "powershell -WindowStyle Hidden -Command" ascii //weight: 10
        $x_1_23 = {b8 26 2e de e4 ba 8f ea 3b be}  //weight: 1, accuracy: High
        $x_1_24 = {3d d2 34 20 5e 7f ?? 3d 27 db 49 39}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Vidar_KK_2147955082_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Vidar.KK!MTB"
        threat_id = "2147955082"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {54 21 06 00 eb 54 00 00 18 55 00 00 68 21 06 00}  //weight: 20, accuracy: High
        $x_10_2 = {21 57 00 00 90 21 06 00 21 57 00 00 33 57 00 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Vidar_KK_2147955082_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Vidar.KK!MTB"
        threat_id = "2147955082"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {48 8b 84 24 90 00 00 00 48 83 c0 14 4c 8b 94 24 a8 00 00 00 44 8b 8c 24 8c 00 00 00 4c 89 c2 4d 89 d0 66 90}  //weight: 20, accuracy: High
        $x_10_2 = {48 8d 3c 03 4c 8d 04 33 45 0f b6 00 44 88 07 48 ff c3}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Vidar_KK_2147955082_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Vidar.KK!MTB"
        threat_id = "2147955082"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {48 8d 1c 02 48 8b b4 24 ?? 00 00 00 48 01 d6 0f b6 36 40 88 33 48 ff c2}  //weight: 20, accuracy: Low
        $x_10_2 = {8b 71 04 48 8b 7c 24 ?? 48 8d 1c 37 48 8b 84 24 ?? 00 00 00 48 8b 8c 24 ?? 00 00 00 48 8b 54 24}  //weight: 10, accuracy: Low
        $x_5_3 = "main.GetInstallDetailsPayload" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Vidar_MK_2147955286_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Vidar.MK!MTB"
        threat_id = "2147955286"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {48 74 74 70 41 64 64 52 65 71 75 65 73 74 48 65 61 64 65 72 73 41 00 14 10 06}  //weight: 20, accuracy: High
        $x_15_2 = {6e 90 00 00 78 a8 05 00 6e 90 00 00 1e 92 00 00 90 a8 05 00 1e 92 00 00 d8 95}  //weight: 15, accuracy: High
        $x_3_3 = {2b 99 00 00 11 9e 00 00 a8 a8 05 00 14 9e 00 00 3d a6}  //weight: 3, accuracy: High
        $x_2_4 = {92 b4 00 00 f6 b4 00 00 44 a9 05 00 f8 b4 00 00 e3 b5 00 00 50 a9 05 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Vidar_MKA_2147955468_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Vidar.MKA!MTB"
        threat_id = "2147955468"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_15_1 = {d2 dc d0 cf a0 ca d1 d6 19 cb c6 91 15 bf 4f 01 e3 7c 81 e3 ff c4 fb b1 71 a4 47 8b a9 02}  //weight: 15, accuracy: High
        $x_10_2 = {2e 69 64 61 74 61 20 20 00 10 00 00 00 90 0d}  //weight: 10, accuracy: High
        $x_5_3 = {40 00 00 e0 2e 72 73 72 63 00 00 00 a8 03}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Vidar_MKB_2147955469_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Vidar.MKB!MTB"
        threat_id = "2147955469"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_15_1 = {66 0f 6e c8 f3 0f e6 c9 f3 0f e6 c0 f2 0f 58 c0 f2 0f 5c c8 f2 0f 59 ca f2 0f 11 4c 24 40 0f be 05 67 c4 02}  //weight: 15, accuracy: High
        $x_10_2 = {44 0f be f8 03 ce 41 8b ff 0f af fb 44 8d 04 bf 42 8d 04 41 41 f7 f1 41 3b c2}  //weight: 10, accuracy: High
        $x_5_3 = "Searching for encrypted_key" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Vidar_ARR_2147956043_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Vidar.ARR!MTB"
        threat_id = "2147956043"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_15_1 = {46 8a 1c 12 45 30 c3 46 88 1c 11 41 bb}  //weight: 15, accuracy: High
        $x_5_2 = {41 0f be 55 00 49 ff c5 85 d2 41 b8 ?? ?? ?? ?? 44 0f 44 c3 eb ?? 41 89 c8 41 c1 e0 ?? 01 d1 44 01 c1 41 b8}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Vidar_ARR_2147956043_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Vidar.ARR!MTB"
        threat_id = "2147956043"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f be d0 8b ce 0f af cd 8d 04 49 03 d0}  //weight: 10, accuracy: High
        $x_7_2 = {8d 04 5a 41 03 c0 33 d2 f7 f1 44 8b c0 0f be 05}  //weight: 7, accuracy: High
        $x_3_3 = {0f 57 c0 6b c3 ?? 03 c6 41 03 c0 f7 f1 44 8b c0 0f be 05}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Vidar_ARR_2147956043_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Vidar.ARR!MTB"
        threat_id = "2147956043"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f 57 c9 f2 48 0f 2a c9 f2 0f 59 c8 f2 0f 10 15 ?? ?? ?? ?? f2 0f 59 ca f2 0f 11 8c c4}  //weight: 5, accuracy: Low
        $x_10_2 = {48 8d 0c 89 0f 57 d2 f2 48 0f 2a d1 f2 0f 58 c2 48 ff c0 48 83 f8}  //weight: 10, accuracy: High
        $x_3_3 = "main.main.func4.main.func4.14.23.10" ascii //weight: 3
        $x_2_4 = "main.main.func1.main.func1.14.23.12" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Vidar_AR_2147956123_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Vidar.AR!MTB"
        threat_id = "2147956123"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {0b 02 0e 2c 00 40 09 00 00 1a}  //weight: 3, accuracy: High
        $x_2_2 = {50 0d 00 00 10 00 00 00 e0 04 00}  //weight: 2, accuracy: High
        $x_1_3 = {60 0d 00 00 04 00 00 00 f0 04 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Vidar_ATR_2147956470_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Vidar.ATR!MTB"
        threat_id = "2147956470"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8a 1c 32 44 30 c3 88 1c 31 8b 3d ?? ?? ?? ?? 8d 6f ?? 0f af ef}  //weight: 5, accuracy: Low
        $x_3_2 = {44 0f af f8 41 f6 c7 ?? b8 ?? ?? ?? ?? 41 0f 44 c6}  //weight: 3, accuracy: Low
        $x_2_3 = {48 8b 45 e8 48 8b 45 f0 8b 05 ?? ?? ?? ?? 8d 50 ?? 0f af d0 f6 c2}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Vidar_YNE_2147956500_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Vidar.YNE!MTB"
        threat_id = "2147956500"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {b9 46 46 77 ff b8 77 ef 45 56 81 f9 46 46 77 ff 74 12 81 f9 77 ef 45 56}  //weight: 10, accuracy: High
        $x_1_2 = {81 fa 9e 74 [0-4] 60 7f 14 81 fa f4 09 48 e3 74 [0-4] 81 fa bf e5 5b 2b 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Vidar_YNF_2147956530_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Vidar.YNF!MTB"
        threat_id = "2147956530"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_11_1 = {42 8a 04 38 4c 8b 7d d0 41 32 07 4c 8b 7d e0}  //weight: 11, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Vidar_GMT_2147956637_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Vidar.GMT!MTB"
        threat_id = "2147956637"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {66 0f 38 1d f0 66 0f 6d fb 41 88 0c 08 48 ff c1 66 0f 38 1d f0 66 0f 6d fb 48 83 f9 72 ?? ?? 48 31 c9 ?? 48 ff c2 66 0f 38 1d f0 66 0f 6d fb 48 81 fa}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Vidar_GRX_2147956980_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Vidar.GRX!MTB"
        threat_id = "2147956980"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {81 c3 25 3a d5 74 41 ff cb 41 81 eb 35 3e 63 67 45 29 de 41 81 eb a7 f8 f2 77 41 01 d3 41 81 c3 a7 f8 f2 77 41 56 81 34 24 13 d3 7d 47 58 35 13}  //weight: 5, accuracy: High
        $x_4_2 = {60 81 f9 0b 41 29 de 41 81 c6 60 81 f9 0b 41 b8 30 d8 de 3f 41 81 e8 2a 54 df e3 45 89 c5 41 c1 e5 05 41 c1 ed 08 41 f7 dd 41 81 ed 93 45 20 f0}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Vidar_SUPC_2147956994_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Vidar.SUPC!MTB"
        threat_id = "2147956994"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 20 20 00 20 20 20 20 00 70 0d 00 00 10 00 00 00 e4 04 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 a8 03 00 00 00 80 0d 00 00 04 00 00 00 f4 04 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 64 61 74 61 20 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Vidar_SPPX_2147957721_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Vidar.SPPX!MTB"
        threat_id = "2147957721"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 20 20 20 20 20 20 20 10 00 00 00 00 b0 01 00 00 02 00 00 00 da 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 20 20 20 20 20 20 20 20 20 2c 00 00 00 c0 01 00 00 18 00 00 00 dc 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 40 2e 62 73 73 00 00 00 00 e0 a3 00 00 00 f0 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Vidar_LPQ_2147957868_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Vidar.LPQ!MTB"
        threat_id = "2147957868"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {44 0f b6 c8 48 8d 52 01 43 0f b6 0c 11 41 8d 04 0b 44 0f b6 d8 43 0f b6 04 13 43 88 04 11 43 88 0c 13 43 0f b6 04 11 48 03 c8 0f b6 c1 42 0f b6 0c 10 30 4a ff 49 83 e8 01 75}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Vidar_AHC_2147958441_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Vidar.AHC!MTB"
        threat_id = "2147958441"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {f2 0f 59 c1 f2 0f 10 94 c4 ?? ?? 00 00 f2 0f 10 ?? ?? ?? ?? ?? f2 0f 59 d3 f2 0f 58 d0 f2 0f 11 94 c4 ?? ?? 00 00 48 ff c0}  //weight: 30, accuracy: Low
        $x_20_2 = {f2 0f 10 84 c4 ?? ?? 00 00 48 89 c1 48 b8 ?? ?? ?? ?? ?? ?? ?? ?? 48 f7 e9 48 01 ca 48 d1 fa 48 8d 14 52 48 89 c8 48 29 d0}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Vidar_GTD_2147958451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Vidar.GTD!MTB"
        threat_id = "2147958451"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "File Grabber Rules" ascii //weight: 1
        $x_1_2 = "Wallet Rules" ascii //weight: 1
        $x_1_3 = "Chromium Plugins" ascii //weight: 1
        $x_1_4 = "Loader Tasks" ascii //weight: 1
        $x_1_5 = "CreateRemoteThread" ascii //weight: 1
        $x_2_6 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 00 a0 82 97 84 81 81 8c c2 d8 c3 dd}  //weight: 2, accuracy: High
        $x_2_7 = {44 48 46 4a 48 48 50 4b 4c 51 5c 0b 46 4a 48 25}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Vidar_XTP_2147958535_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Vidar.XTP!MTB"
        threat_id = "2147958535"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b6 f8 48 8d 52 01 0f b6 4c 3c 50 41 8d 04 08 44 0f b6 c0 42 0f b6 44 04 50 88 44 3c 50 42 88 4c 04 50 0f b6 44 3c ?? 03 c1 0f b6 c0 0f b6 4c 04 50 30 4a ff 49 83 e9 01 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Vidar_AHD_2147958814_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Vidar.AHD!MTB"
        threat_id = "2147958814"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {48 89 c1 48 b8 ?? ?? ?? ?? ?? ?? ?? ?? 48 f7 e9 48 01 ca 48 d1 fa 48 8d 14 52 48 89 cb 48 29 d1 48 85 c9 75}  //weight: 30, accuracy: Low
        $x_20_2 = {48 be b8 1e 85 eb 51 b8 9e 3f 48 89 b4 24 ?? ?? ?? ?? 48 be 7b 14 ae 47 e1 7a 84 bf 48 89 b4 24 ?? ?? ?? ?? 48 be 7b 14 ae 47 e1 7a a4 3f}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Vidar_ASVD_2147958995_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Vidar.ASVD!MTB"
        threat_id = "2147958995"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {44 0f b7 40 24 48 8b 85 10 07 00 00 48 8b 50 18 48 8b 0d 48 a1 12 00 48 83 ec 40 45 31 ff 4c 89 7c 24 38 4c 89 7c 24 20 c7 44 24 30 00 00 00 00 c7 44 24 28 03 00 00 00 45 31 c9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Vidar_AVA_2147959014_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Vidar.AVA!MTB"
        threat_id = "2147959014"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "bky7-KdahWdaal" ascii //weight: 5
        $x_4_2 = "WEmbTRDCXEH" ascii //weight: 4
        $x_3_3 = "6276!SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS" ascii //weight: 3
        $x_2_4 = "WgggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggTdubbitohs" ascii //weight: 2
        $x_1_5 = "QRccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccWallet Rules" ascii //weight: 1
        $x_6_6 = "bONE_B_RxNY]BHN" ascii //weight: 6
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Vidar_AHE_2147959354_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Vidar.AHE!MTB"
        threat_id = "2147959354"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Vidar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {48 89 cb 48 c1 f9 ?? 48 c1 e1 ?? 48 89 de 48 29 cb 66 0f 1f 44 00 00 48 83 fb ?? 72}  //weight: 20, accuracy: Low
        $x_30_2 = {48 c7 84 24 30 01 00 00 91 00 00 00 48 c7 84 24 38 01 00 00 16 01 00 00 48 c7 84 24 40 01 00 00 88 01 00 00 48 c7 84 24 48 01 00 00 c3 01 00 00}  //weight: 30, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

