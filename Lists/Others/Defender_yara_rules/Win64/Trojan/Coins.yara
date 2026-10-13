rule Trojan_Win64_Coins_MK_2147959565_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Coins.MK!MTB"
        threat_id = "2147959565"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Coins"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_30_1 = {48 b8 4b 65 79 20 62 6c 6f 62 48 89 04 33 66 c7 44 33 08 3a 20 c6 44 33 0a 00 48 8d 8d e0 04 00 00 4c 8d 85 a0 07 00 00 4c 89 fa}  //weight: 30, accuracy: High
        $x_3_2 = "=== ABE v7 Full Extraction (Handle Duplication) ===" ascii //weight: 3
        $x_2_3 = "ABE Key Extract - Passwords" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Coins_MK_2147959565_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Coins.MK!MTB"
        threat_id = "2147959565"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Coins"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "KeyLogger Error: Logs directory not found or empty." ascii //weight: 5
        $x_5_2 = "Received command: START_REVERSE_SHELL" ascii //weight: 5
        $x_5_3 = "Received command: STOP_REVERSE_SHELL" ascii //weight: 5
        $x_5_4 = "Received command: SEND_REVERSE_SHELL" ascii //weight: 5
        $x_5_5 = "Expircy:" ascii //weight: 5
        $x_5_6 = "Cookies Browser:" ascii //weight: 5
        $x_5_7 = "password collection complete. Uploading ZIP file:" ascii //weight: 5
        $x_2_8 = "BraveSoftware\\Brave-Browser\\User Data" ascii //weight: 2
        $x_2_9 = "Microsoft\\Edge\\User Data" ascii //weight: 2
        $x_1_10 = "Google\\Chrome\\User Data" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Coins_AH_2147964411_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Coins.AH!MTB"
        threat_id = "2147964411"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Coins"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "nL2@wQ5$pX8zR1mK4cF7hJ0eT3yU6iO9aS2dG5fH8jK1lZ4xC7vB0nM3qW6tY9" ascii //weight: 20
        $x_30_2 = {48 33 c1 48 89 45 00 48 8b 45 08 48 89 45 08 48 8b 45 08 48 8b 4d 00 48 33 c8 48 89 4d 00 eb}  //weight: 30, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Coins_AMCI_2147971663_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Coins.AMCI!MTB"
        threat_id = "2147971663"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Coins"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8a 02 48 ff c2 3c ?? ?? ?? 83 f0 ?? 48 83 c1 02 0f b6 c0 66 89 41}  //weight: 5, accuracy: Low
        $x_5_2 = {48 89 c2 83 e2 ?? 8a 14 11 32 14 06 88 14 03 48 ff c0 eb e8}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Coins_A_2147977095_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Coins.A!MTB"
        threat_id = "2147977095"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Coins"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "55"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "Discord browser scan failed:" ascii //weight: 20
        $x_15_2 = "Discord user-dir scan failed:" ascii //weight: 15
        $x_10_3 = "Discord browser scan phase failed" ascii //weight: 10
        $x_5_4 = "Discord user-dir scan phase failed" ascii //weight: 5
        $x_3_5 = "cuckoomon.dll" ascii //weight: 3
        $x_2_6 = "wpespy.dll" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Coins_PC_2147977889_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Coins.PC!MTB"
        threat_id = "2147977889"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Coins"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {49 39 ca 74 ?? 48 89 c8 31 d2 48 ff c1 49 f7 f1 41 8a 04 13 41 30 00 49 ff c0 eb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

