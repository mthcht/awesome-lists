rule Trojan_Win64_VidarStealer_ABA_2147955945_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/VidarStealer.ABA!MTB"
        threat_id = "2147955945"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "VidarStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {ff c0 48 63 c8 48 8d 54 24 ?? 48 03 d1 0f b6 0a 41 88 0c 18 44 88 0a 41 0f b6 14 18 49 03 d1 0f b6 ca 0f b6 54 0c ?? 30 17 48 ff c7 49 83 ea}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_VidarStealer_ABA_2147955945_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/VidarStealer.ABA!MTB"
        threat_id = "2147955945"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "VidarStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {ff c2 0f b6 d2 44 0f b6 84 14 ?? ?? ?? ?? 44 00 c1 44 0f b6 c9 46 0f b6 94 0c ?? ?? ?? ?? 44 88 94 14 ?? ?? ?? ?? 46 88 84 0c ?? ?? ?? ?? 44 02 84 14 ?? ?? ?? ?? 45 0f b6 c0 46 0f b6 84 04 ?? ?? ?? ?? 45 30 04 04 48 ff c0 49 39 c3}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_VidarStealer_RH_2147956212_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/VidarStealer.RH!MTB"
        threat_id = "2147956212"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "VidarStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "//telegram.me/k0ddr" ascii //weight: 2
        $x_1_2 = "Chromium Plugins" ascii //weight: 1
        $x_1_3 = "File Grabber Rules" ascii //weight: 1
        $x_1_4 = "Wallet Rules" ascii //weight: 1
        $x_1_5 = "Browser List" ascii //weight: 1
        $x_1_6 = "Firefox Plugins" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_VidarStealer_RH_2147956212_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/VidarStealer.RH!MTB"
        threat_id = "2147956212"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "VidarStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {50 45 00 00 64 86 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 02 0e 2c ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 3c ac}  //weight: 3, accuracy: Low
        $x_2_2 = "Browser List" ascii //weight: 2
        $x_2_3 = "Chromium Plugins" ascii //weight: 2
        $x_2_4 = "Firefox Plugins" ascii //weight: 2
        $x_2_5 = "Wallet Rules" ascii //weight: 2
        $x_2_6 = "File Grabber Rules" ascii //weight: 2
        $x_1_7 = "Loader Tasks" ascii //weight: 1
        $x_1_8 = "\\ProgramData\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_VidarStealer_ARAX_2147956832_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/VidarStealer.ARAX!MTB"
        threat_id = "2147956832"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "VidarStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "fuck_wacatac" ascii //weight: 2
        $x_2_2 = "--remote-debugging-port=9223 --profile-directory=\"Default\"" ascii //weight: 2
        $x_2_3 = "passwords.txt" ascii //weight: 2
        $x_2_4 = "_formhistory.db" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_VidarStealer_AMB_2147957083_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/VidarStealer.AMB!MTB"
        threat_id = "2147957083"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "VidarStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {41 ff c1 49 63 c9 42 8a 04 19 43 88 04 1a 42 88 1c 19 43 0f b6 0c 1a 48 03 cb 0f b6 c1 42 8a 0c 18 30 0f 48 ff c7 49 83 e8}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_VidarStealer_AD_2147957457_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/VidarStealer.AD!MTB"
        threat_id = "2147957457"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "VidarStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {4c 89 54 24 08 48 c1 c8 13 49 33 c8 48 89 44 24 18 33 c0 48 89 1c 24 48 89 4c 24 10 8d 0c c5 ?? ?? ?? ?? 4d 8b c1 49 d3 e8 ff c0 44 32 04 32 44 88 44 14 20 48 ff c2 48 83 fa}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_VidarStealer_KK_2147959872_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/VidarStealer.KK!MTB"
        threat_id = "2147959872"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "VidarStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_9_1 = "Browser List" ascii //weight: 9
        $x_8_2 = "Chromium Plugins" ascii //weight: 8
        $x_7_3 = "Firefox Plugins" ascii //weight: 7
        $x_6_4 = "Wallet Rules" ascii //weight: 6
        $x_5_5 = "File Grabber Rules" ascii //weight: 5
        $x_4_6 = "Loader Tasks" ascii //weight: 4
        $x_3_7 = "chrome" ascii //weight: 3
        $x_2_8 = "firefox" ascii //weight: 2
        $x_1_9 = "opera" ascii //weight: 1
        $x_5_10 = {48 ff c0 88 17 83 e9 01 8a 10 48 8d 7f 01}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

