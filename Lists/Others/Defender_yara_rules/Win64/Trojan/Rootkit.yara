rule Trojan_Win64_Rootkit_ARA_2147910200_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rootkit.ARA!MTB"
        threat_id = "2147910200"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rootkit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = ":\\Users\\Baat\\Desktop\\GPT 1.6\\x64\\Release\\RWSafe.pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rootkit_OJAA_2147915225_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rootkit.OJAA!MTB"
        threat_id = "2147915225"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rootkit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {41 0f b7 c2 48 8d 0c 80 41 8b 54 c9 2c 45 8b 44 c9 28 48 03 d3 41 8b 4c c9 24 48 03 ce e8 70 e3 ff ff 66 45 03 d4 66 44 3b 57 06 72}  //weight: 4, accuracy: High
        $x_1_2 = "ReflectiveDllMain" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rootkit_MBXH_2147915634_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rootkit.MBXH!MTB"
        threat_id = "2147915634"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rootkit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f 85 94 4a 02 00 41 89 49 08 49 f7 c1 06 61 e3 46 45 89 51 04 44 3a dc 41 80 f8 09 e9 23 34 17 00 c1 63 6b 6f 1d 89 b1 df 27 c5 4b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rootkit_EH_2147920392_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rootkit.EH!MTB"
        threat_id = "2147920392"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rootkit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {4c 8d 4c 24 38 48 8d 54 24 48 41 bc 00 d0 00 00 45 33 c0 48 8b cb c7 44 24 28 40 00 00 00 c7 44 24 20 00 10 00 00 4c 89 64 24 38}  //weight: 10, accuracy: High
        $x_1_2 = "workspace4\\lock\\hpsafe\\src\\sys\\objfre_win7_amd64\\amd64\\hpsafe.pdb" ascii //weight: 1
        $x_1_3 = "Registry\\Machine\\System\\CurrentControlSet\\Services\\MpDriver" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rootkit_GZT_2147921675_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rootkit.GZT!MTB"
        threat_id = "2147921675"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rootkit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {89 4c 24 08 48 83 ec 38 48 8b 4c 24 40 ff 15 e7 47 01 00 48 89 44 24 20 48 83 7c 24 20 00 74 17 48 8b 54 24}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rootkit_CCIM_2147923916_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rootkit.CCIM!MTB"
        threat_id = "2147923916"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rootkit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8d 44 24 38 41 b9 3f 01 0f 00 45 33 c0 48 89 44 24 20 48 8d 15 5a 33 01 00 48 c7 c1 02 00 00 80 ff 15 2d bc 00 00 85 c0 75 12 48 8b 4c 24 38 48 8d 15 55 33 01 00 ff 15 f7 bb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rootkit_CCJN_2147925694_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rootkit.CCJN!MTB"
        threat_id = "2147925694"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rootkit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 83 64 24 40 00 48 8d 54 24 40 48 8b c8 ff 15 ?? ?? ?? ?? 8b f8 85 c0 78 ?? 8b 4b 04 48 83 64 24 48 00 48 89 4c 24 50 48 8b 4c 24 40 ff 15 ?? ?? ?? ?? 8b 4b 08 4c 8d 4c 24 50 89 4c 24 28 48 8d 54 24 48 48 83 c9 ff c7 44 24 20 00 30 00 00 45 33 c0 ff 15 ?? ?? ?? ?? ff 15}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rootkit_EM_2147928047_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rootkit.EM!MTB"
        threat_id = "2147928047"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rootkit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Masonconfig" ascii //weight: 1
        $x_1_2 = "\\\\.\\pipe\\Masonchildproc64" ascii //weight: 1
        $x_1_3 = "\\\\.\\pipe\\Masonchildproc32" ascii //weight: 1
        $x_1_4 = "ReflectiveDllMain" ascii //weight: 1
        $x_1_5 = ".detour" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Rootkit_LM_2147960483_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Rootkit.LM!MTB"
        threat_id = "2147960483"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Rootkit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {41 8b 11 45 33 d2 49 03 d0 eb ?? 41 c1 ca 0d 0f be c0 44 03 d0 48 ff c2 8a 02 84 c0 75 ?? 44 3b d6 74 1e ff c3 49 83 c1 04 48 83 c1 02}  //weight: 20, accuracy: Low
        $x_10_2 = {48 63 48 3c 33 db 44 8b 9c 01 88 00 00 00 45 8b 4c 03 20 41 8b 4c 03 24 4c 03 c8 48 03 c8 41 39 5c 03 18}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

