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

