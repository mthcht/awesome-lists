rule Trojan_Win64_DiscordStealer_AHB_2147946419_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DiscordStealer.AHB!MTB"
        threat_id = "2147946419"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DiscordStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f 57 c0 0f 11 45 ?? 4c 89 ?? ?? 4c 89 ?? ?? 0f 10 00 0f 11 45 ?? 0f 10 48 10 0f 11 4d ?? 4c 89 ?? 10 48 c7 40 18 0f 00 00 00 c6 00 00 48 8b 54 24 ?? 48 83 fa 0f}  //weight: 5, accuracy: Low
        $x_1_2 = "\\Local Storage\\leveldb" ascii //weight: 1
        $x_1_3 = "webhook.site" ascii //weight: 1
        $x_1_4 = "\\discordcanary" ascii //weight: 1
        $x_1_5 = "\\Lightcord" ascii //weight: 1
        $x_1_6 = "\\discordptb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DiscordStealer_ARA_2147954784_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DiscordStealer.ARA!MTB"
        threat_id = "2147954784"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DiscordStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Successfully sent PC information to Discord" ascii //weight: 2
        $x_2_2 = "Computer Name" ascii //weight: 2
        $x_2_3 = "Username" ascii //weight: 2
        $x_2_4 = "OS Version" ascii //weight: 2
        $x_2_5 = "CPU Info" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DiscordStealer_ARR_2147957360_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DiscordStealer.ARR!MTB"
        threat_id = "2147957360"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DiscordStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {31 d2 44 8b 44 24 ?? f7 f1 44 01 c2 89 54 24}  //weight: 2, accuracy: Low
        $x_8_2 = {89 c2 41 32 01 49 83 c1 ?? 0f b6 c0 c1 ea ?? 33 14 81 89 d0 4d 39 d1}  //weight: 8, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DiscordStealer_ND_2147959837_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DiscordStealer.ND!MTB"
        threat_id = "2147959837"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DiscordStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {c6 40 01 00 48 8b b4 24 58 01 00 00 48 89 ac 24 e0 01 00 00 48 8b bc 24 50 01 00 00 48 8d 56 09 c6 84 24 f0 01 00 00 00 48 c7 84 24 e8 01}  //weight: 2, accuracy: High
        $x_1_2 = "Stealer Bot" ascii //weight: 1
        $x_1_3 = "pcinfo.txt" ascii //weight: 1
        $x_1_4 = "wmic cpu get ProcessorId" ascii //weight: 1
        $x_1_5 = "Login Data" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

