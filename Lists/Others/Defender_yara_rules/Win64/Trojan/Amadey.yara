rule Trojan_Win64_Amadey_CA_2147838642_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Amadey.CA!MTB"
        threat_id = "2147838642"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SELECT origin_url, username_value, password_value FROM logins" ascii //weight: 1
        $x_1_2 = "\\Google\\Chrome\\User Data\\Default\\Login Data" ascii //weight: 1
        $x_1_3 = "\\Opera Software\\Opera Stable\\Login Data" ascii //weight: 1
        $x_1_4 = "PK11SDR_Decrypt" ascii //weight: 1
        $x_1_5 = "\\Mozilla\\Firefox\\Profiles\\" ascii //weight: 1
        $x_1_6 = "\\logins.json" ascii //weight: 1
        $x_1_7 = "Exodus\\exodus.wallet\\" ascii //weight: 1
        $x_1_8 = "electrum_data\\wallets" ascii //weight: 1
        $x_1_9 = "Taskkill /IM ArmoryQt.exe /F" ascii //weight: 1
        $x_1_10 = "Dogecoin\\" ascii //weight: 1
        $x_1_11 = "STEALERDLL.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Amadey_CX_2147838966_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Amadey.CX!MTB"
        threat_id = "2147838966"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {49 87 cf 49 89 c7 4c 87 f9 c6 04 10 ?? 80 34 10 ?? 80 2c 10 ?? 80 04 10 ?? 80 2c 10 ?? 48 d1 e1 48 c1 e1 ?? 48 d1 e1 48 ?? ?? ?? ?? ?? ?? 48 03 c8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Amadey_CAV_2147843705_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Amadey.CAV!MTB"
        threat_id = "2147843705"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "D:\\Mktmp\\Amadey\\StealerDLL" ascii //weight: 1
        $x_1_2 = "\\Google\\Chrome\\User Data\\Default\\Login Data" ascii //weight: 1
        $x_1_3 = "\\Opera Software\\Opera Stable\\Login Data" ascii //weight: 1
        $x_1_4 = "\\Microsoft\\Edge\\User Data\\Default\\Login Data" ascii //weight: 1
        $x_1_5 = "\\Chedot\\User Data\\Default\\Login Data" ascii //weight: 1
        $x_1_6 = "\\CentBrowser\\User Data\\Default\\Login Data" ascii //weight: 1
        $x_1_7 = "encryptedUsername\":" ascii //weight: 1
        $x_1_8 = "encryptedPassword\":" ascii //weight: 1
        $x_1_9 = "Monero\\wallets\\" ascii //weight: 1
        $x_1_10 = "logins.json" ascii //weight: 1
        $x_1_11 = "SELECT origin_url, username_value, password_value FROM logins" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Amadey_RDL_2147894701_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Amadey.RDL!MTB"
        threat_id = "2147894701"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Mozilla\\Firefox\\Profiles\\" ascii //weight: 1
        $x_1_2 = "\\TorBrowser\\Data\\Browser\\profile.default" ascii //weight: 1
        $x_1_3 = "\"encryptedPassword\":\"([^\"]+)\"" ascii //weight: 1
        $x_1_4 = "\\logins.json" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Amadey_A_2147902053_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Amadey.A!MTB"
        threat_id = "2147902053"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "encryptedUsername" ascii //weight: 2
        $x_2_2 = "encryptedPassword" ascii //weight: 2
        $x_2_3 = "netsh wlan export profile name" ascii //weight: 2
        $x_2_4 = "netsh wlan show profiles" ascii //weight: 2
        $x_2_5 = "hostname" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Amadey_B_2147902169_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Amadey.B!MTB"
        threat_id = "2147902169"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "password type=\"QString" ascii //weight: 2
        $x_2_2 = "Pass encoding=\"base64" ascii //weight: 2
        $x_2_3 = "netsh wlan export profile name" ascii //weight: 2
        $x_2_4 = "netsh wlan show profiles" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Amadey_COP_2147931423_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Amadey.COP!MTB"
        threat_id = "2147931423"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e8 a5 f6 ff ff 48 89 05 42 59 00 00 48 8d 15 e3 44 00 00 48 8d 0d ec 44 00 00 e8 8b f6 ff ff 48 89 05 30 59 00 00 48 8d 15 e9 44 00 00 48 8d 0d fa 44 00 00 e8 71 f6 ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Amadey_AUJ_2147931424_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Amadey.AUJ!MTB"
        threat_id = "2147931424"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {eb 08 0f 94 5d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Amadey_BS_2147935304_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Amadey.BS!MTB"
        threat_id = "2147935304"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {4c 0f 47 45 c8 ba 12 27 00 00 48 8b c8 e8 ?? ?? 00 00 4c 8d 05 ?? ?? ff ff ba 2b 4e 00 00 48 8b cb e8 ?? ?? 00 00 4c 8d 45 a8 ba 11 27 00 00 48 8b cb}  //weight: 4, accuracy: Low
        $x_1_2 = {0f b6 c1 2a c2 04 ?? 41 30 01 ff c1 4d 8d 49 01 83 f9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Amadey_AMA_2147947183_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Amadey.AMA!MTB"
        threat_id = "2147947183"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 98 48 01 d0 0f b6 00 32 45 20 89 c1 48 8b 55 28 8b 45 fc 48 98 48 01 d0 88 08 8b 4d fc}  //weight: 2, accuracy: High
        $x_1_2 = {48 98 48 01 d0 88 08 8b 4d fc 48 63 c1 48 69 c0 ?? ?? ?? ?? 48 c1 e8 20 48 89 c2 89 c8 c1 f8 1f 29 c2 89 d0 01 c0 01 d0 29 c1 89 ca 85 d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Amadey_ADZM_2147948058_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Amadey.ADZM!MTB"
        threat_id = "2147948058"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 1b 48 83 7c 24 ?? ?? 48 8d 54 24 ?? 4c 8b c3 48 c7 44 24 ?? ?? ?? ?? ?? 48 0f 47 54 24 ?? 45 33 c9 33 c9 e8 ?? ?? ?? ?? 48 8b 54 24 ?? 8b d8 c1 eb 1f 80 f3 01 48 83 fa 07}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Amadey_ADM_2147952325_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Amadey.ADM!MTB"
        threat_id = "2147952325"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "xabanak.ru/build.exe" wide //weight: 5
        $x_3_2 = "TEMP\\au.txt" wide //weight: 3
        $x_2_3 = "File Download" wide //weight: 2
        $x_1_4 = "runas" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Amadey_AMD_2147954412_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Amadey.AMD!MTB"
        threat_id = "2147954412"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 f7 e9 48 01 ca 48 d1 fa 48 89 cb 48 c1 f9 3f 48 29 ca 48 85 d2 0f 8e a4 00 00 00 48 8b 44 24 68 48 89 d1 48 89 c6 48}  //weight: 2, accuracy: High
        $x_1_2 = {48 89 44 24 18 48 8b 10 48 8d 59 ff 48 89 1c 24 48 8b 1a ff d3 48 8b 44 24 08 48 89 44 24 10 48 8b 4c 24 18 48 8b 11 48 8b 4c 24 30 48 83 c1 fe}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Amadey_AMD_2147954412_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Amadey.AMD!MTB"
        threat_id = "2147954412"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8d 15 c1 7d 07 00 48 8b c8 ff 15 ?? ?? ?? ?? 48 8d 15 c1 7d 07 00 48 8b cf 48 89 05 67 8a 07 00 ff 15 ?? ?? ?? ?? 48 8d 15 c2 7d 07 00 48 8b cf 48 89 05 58 8a 07 00 ff 15 ?? ?? ?? ?? 48 8d 15 c3 7d 07 00 48 8b cf 48 89 05 49 8a 07 00 ff 15 ?? ?? ?? ?? 48 8d 15 bc 7d 07 00 48 8b cf 48 89 05 3a 8a 07 00 ff 15 ?? ?? ?? ?? 48 8d 15 bd 7d 07 00 48 8b cf}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Amadey_PGAS_2147954633_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Amadey.PGAS!MTB"
        threat_id = "2147954633"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8f e8 1f a8 68 7d bf f9 bb 6b e9 6a 3b ee c1 7a 63 c1 9f ef c7 03 ea f2 43 89 69 4a e0 7e 5e 0a 5f 7f e8 75 35 ea 52 13 f4 67 2f 28 04 99 06 c6 c9 5e 6d bc 18 a5}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Amadey_MMX_2147955151_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Amadey.MMX!MTB"
        threat_id = "2147955151"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {b1 aa f3 3b 80 4c 28 8d 08 61 02 58 6b 55 89 11 66 e0 ce ?? 4f ea b9 0f e3 44 81 e2 a2 93 d1 69 71 48 3a 00 51 47 ab 3c ac 19 05 00 53 eb 52 5a}  //weight: 5, accuracy: Low
        $x_5_2 = {56 50 53 e8 01 00 00 00 ?? 58 48 89 c3 48 ff c0 48 2d 00 80 20 00 48 2d 24 2f 0c 10 48 05 1b 2f 0c 10 80 3b cc 75 19 c6 03 00 bb 00 10 00 00 68}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Amadey_GXF_2147955415_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Amadey.GXF!MTB"
        threat_id = "2147955415"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {41 b9 00 30 00 00 41 b8 00 10 00 00 33 d2 48 8b 4c 24 30 ff 15}  //weight: 5, accuracy: High
        $x_5_2 = {48 8b 44 24 38 48 89 44 24 49 48 8b 44 24 58 48 83 c0 0a 48 8b 4c 24 68 48 2b c8 48 8b c1 48 89 44 24 4e 48 c7 44 24 20 00 00 00 00 41 b9 0b 00 00 00 4c 8d 44 24 48 48 8b 54 24 58 48 8b 4c 24 30 ff 15}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Amadey_PGAP_2147955445_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Amadey.PGAP!MTB"
        threat_id = "2147955445"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {41 8b c1 4d 8d 5b 01 4d 0f 47 c7 4d 8d 52 01 33 d2 41 ff c1 41 f7 f6 42 0f b6 04 02 41 32 42 ff 41 88 43 ff 41 81 f9}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Amadey_PGAP_2147955445_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Amadey.PGAP!MTB"
        threat_id = "2147955445"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 63 cf 48 8d 55 ?? 48 03 d1 0f b6 0a 41 88 09 44 88 12 41 0f b6 11 49 03 d2 0f b6 ca 0f b6 54 0d ?? 41 30 10 49 ff c0 49 83 eb ?? 75 9d}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Amadey_NR_2147956162_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Amadey.NR!MTB"
        threat_id = "2147956162"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {49 89 d1 48 f7 ea 48 d1 fa 4c 8d 14 52 4a 8d 14 52 4c 89 c8 49 29 d1 49 83 f9 02 0f 8f b9 02 00 00}  //weight: 2, accuracy: High
        $x_1_2 = {48 29 ca 88 50 01 bb 02 00 00 00 48 89 d9 0f 1f 44 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Amadey_GSS_2147956722_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Amadey.GSS!MTB"
        threat_id = "2147956722"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 89 f2 48 03 15 ?? ?? ?? ?? 89 d8 c1 f8 1f c1 e8 1b 01 c3 83 e3 1f 29 c3 48 63 db 0f b6 04 1f 30 02 48 83 c6 01 48 81 fe 4b 4e 07 00 74}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Amadey_Z_2147957088_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Amadey.Z"
        threat_id = "2147957088"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Amadey"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 b8 20 00 00 00 48 8d 15 ?? ?? ?? ?? 48 8d 0d ?? ?? ?? ?? e8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 41 b8 20 00 00 00 48 8d 15 ?? ?? ?? ?? 48 8d 0d ?? ?? ?? ?? e8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 41 b8 06 00 00 00 48 8d 15 ?? ?? ?? ?? 48 8d 0d ?? ?? ?? ?? e8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 41 b8 20 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {41 b8 44 00 00 00 48 8d 15 ?? ?? ?? ?? 48 8d 0d ?? ?? ?? ?? e8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 41 b8 5c 00 00 00 48 8d 15 ?? ?? ?? ?? 48 8d 0d ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_3 = {41 b8 50 00 00 00 48 8d 15 ?? ?? ?? ?? 48 8d 0d ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 8d 0d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 41 b8 40 00 00 00 48 8d 15 ?? ?? ?? ?? 48 8d 0d ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_4 = "DenyTSConnections" ascii //weight: 1
        $x_1_5 = {00 30 31 2d 2d 45 00}  //weight: 1, accuracy: High
        $x_1_6 = {2d 2d 2d 00 35 31 32 30 00 00 00 00 76 6e 63 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_7 = "netsh advfirewall firewall set rule group=\"Remote Desktop\" new enable=Yes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win64_Amadey_MQQ_2147957271_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Amadey.MQQ!MTB"
        threat_id = "2147957271"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {48 89 d8 83 e0 0f 0f b6 84 04 80 00 00 00 32 04 1e 41 88 04 19 48 83 c3 01 48 39 d9 75 e2}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Amadey_Y_2147957969_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Amadey.Y"
        threat_id = "2147957969"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Amadey"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 6f 73 5f 62 61 73 65 3a 3a 65 6f 66 62 69 74 20 73 65 74 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? (30|2d|39|61|2d|66) (30|2d|39|61|2d|66) 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? (30|2d|39|61|2d|66) (30|2d|39|61|2d|66) 00 00 00 00 ?? ?? ?? ?? (30|2d|39|61|2d|66) (30|2d|39|61|2d|66) 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? (30|2d|39|61|2d|66) (30|2d|39|61|2d|66) 00 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Amadey_ABA_2147958447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Amadey.ABA!MTB"
        threat_id = "2147958447"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 03 c8 0f b6 01 41 88 04 19 44 88 11 41 0f b6 0c 19 49 03 ca 0f b6 c1 0f b6 4c 04 ?? 42 32 0c 07 41 88 08 49 ff c0 49 83 eb 01 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Amadey_PGAD_2147959493_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Amadey.PGAD!MTB"
        threat_id = "2147959493"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {3c 4e 6f 6e 65 3e 00 00 3c 4e 6f 6e 65 3e 00 00 00 00 00 00 3c 4e 6f 6e 65 3e 00 00 01 00 00 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 [0-15] 2e 00 76 00 62 00 73 00 [0-42] 3c 4e 6f 6e 65 3e 00 00 3c 4e 6f 6e 65 3e}  //weight: 5, accuracy: Low
        $x_5_2 = {3c 4e 6f 6e 65 3e 00 00 3c 4e 6f 6e 65 3e 00 00 00 00 00 00 3c 4e 6f 6e 65 3e 00 00 01 00 00 00 63 6d 64 2e 65 78 65 20 2f 63 [0-15] 2e 76 62 73 [0-42] 3c 4e 6f 6e 65 3e 00 00 3c 4e 6f 6e 65 3e}  //weight: 5, accuracy: Low
        $x_5_3 = {2e 74 65 78 74 00 00 00 80 7b 00 00 00 10 00 00 80 7b 00 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 60 2e 72 64 61 74 61 00 00 c8 22 00 00 00 90 00 00 c8 22 00 00 00 90 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 40 2e 64 61 74 61}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win64_Amadey_AMTA_2147959537_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Amadey.AMTA!MTB"
        threat_id = "2147959537"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 03 c8 0f b6 01 41 88 04 19 44 88 11 41 0f b6 0c 19 49 03 ca 0f b6 c1 0f b6 4c 04 30 42 32 0c 07 41 88 08 49 ff c0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

