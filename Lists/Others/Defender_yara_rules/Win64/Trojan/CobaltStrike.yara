rule Trojan_Win64_CobaltStrike_2147747812_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike!MTB"
        threat_id = "2147747812"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 40 08 48 2b c1 48 c1 f8 05 48 83 c4 18}  //weight: 1, accuracy: High
        $x_1_2 = {48 89 4c 24 08 48 83 ec 38 48 8b 44 24 40 48 83 c8 0f 48 89 44 24 20 48 8b 44 24}  //weight: 1, accuracy: High
        $x_1_3 = {48 89 4c 24 08 48 83 ec 18 48 8b 44 24 20 48 89 04 24 48 6b 44 24 28 20 48 8b 0c 24 48 03 01 48 83 c4 18}  //weight: 1, accuracy: High
        $x_1_4 = {48 81 c1 00 01 00 00 48 81 c2 00 01 00 00 49 81 e8 00 01 00 00 49 81 f8 00 01 00 00 0f 83 78 ff ff ff}  //weight: 1, accuracy: High
        $x_1_5 = {4d 8d 48 1f 49 83 e1 e0 4d 8b d9 49 c1 eb 05 47 8b 9c 9a 40 b0 1d 00 4d 03 da}  //weight: 1, accuracy: High
        $x_1_6 = {49 81 f8 80 00 00 00 0f 86 8e 00 00 00 4c 8b c9 49 83 e1 0f 49 83 e9 10 49 2b c9 49 2b d1 4d 03 c1 49 81 f8 80}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_SBR_2147762399_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.SBR!MSR"
        threat_id = "2147762399"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\\\.\\pipe\\MSSE-1966-server" ascii //weight: 1
        $x_1_2 = "%c%c%c%c%c%c%c%c%cMSSE-%d-server" ascii //weight: 1
        $x_1_3 = "temp.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_MB_2147776631_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MB!MTB"
        threat_id = "2147776631"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 83 80 00 00 00 48 8b 8b e0 00 00 00 42 31 04 01 49 83 c0 04 8b 83 e8 00 00 00 01 83 80 00 00 00 8b 43 24 ff c8 01 83 d0 00 00 00 8b 83 94 00 00 00 8b 93 a8 00 00 00 81 c2 37 9f fd ff 03 53 74 0f af c2 89 83 94 00 00 00 b8 6f 15 f8 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_MB_2147776631_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MB!MTB"
        threat_id = "2147776631"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {45 33 c0 41 b9 9e 03 00 00 49 8b c0 49 ff c0 83 e0 0f 8a 04 10 30 01 48 ff c1 49 83 e9 01 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_MB_2147776631_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MB!MTB"
        threat_id = "2147776631"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f af c1 89 87 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8b 05 ?? ?? ?? ?? ff c0 0f af c8 89 0d ?? ?? ?? ?? 49 81 f8}  //weight: 1, accuracy: Low
        $x_1_2 = {88 14 01 ff 05 ?? ?? ?? ?? 48 8b 15 ?? ?? ?? ?? 8b 82 ?? ?? ?? ?? 8b 8a ?? ?? ?? ?? 33 c8 81 e9 ?? ?? ?? ?? 0f af c8 89 8a ?? ?? ?? ?? 48 8b 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_MB_2147776631_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MB!MTB"
        threat_id = "2147776631"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 54 84 18 89 d5 c1 c5 [0-1] 89 d3 c1 c3 [0-1] c1 ea [0-1] 31 da 31 ea 8b 6c 84 [0-1] 8b 5c 84 [0-1] 89 df c1 c7 [0-1] 89 de c1 c6 [0-1] c1 eb [0-1] 31 f3 31 fb 03 6c 84 [0-1] 01 d5 01 dd 89 6c 84 [0-1] 48 83 c0 [0-1] 48 83 f8 [0-1] 75}  //weight: 1, accuracy: Low
        $x_1_2 = "broken pipe" ascii //weight: 1
        $x_1_3 = "connection aborted" ascii //weight: 1
        $x_1_4 = "owner dead" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_MB_2147776631_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MB!MTB"
        threat_id = "2147776631"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "AAxgDMxuKzLU" ascii //weight: 2
        $x_2_2 = "AOOuChrTITNyPgdkJjFPTnB" ascii //weight: 2
        $x_2_3 = "AXMqnxlJzDXKKNFgwMCrJUk" ascii //weight: 2
        $x_2_4 = "BYzzBzWVbNjKdXpOPhAm" ascii //weight: 2
        $x_2_5 = "CChQRyUVikMaBGDEGulr" ascii //weight: 2
        $x_2_6 = "CWEMRvwtJNovrrWsIwERjSjD" ascii //weight: 2
        $x_2_7 = "CjjBtZLZkKdkMfRplAW" ascii //weight: 2
        $x_2_8 = "DCQtxlJitMrqLWzy" ascii //weight: 2
        $x_2_9 = "DTZNQxYOXIoturzHrEzRpxu" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_A_2147776992_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.A!MTB"
        threat_id = "2147776992"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Go build ID:" ascii //weight: 1
        $x_1_2 = "NfptVUht8fXAebTMPsvc" ascii //weight: 1
        $x_1_3 = "Nlooo3yPTMrkDcUDHsIW" ascii //weight: 1
        $x_1_4 = "github.com/mitre/gocat/" ascii //weight: 1
        $x_1_5 = "evaluateWatchdog" ascii //weight: 1
        $x_1_6 = "key expansion" ascii //weight: 1
        $x_1_7 = "master secret" ascii //weight: 1
        $x_1_8 = "client finished" ascii //weight: 1
        $x_1_9 = "server finished" ascii //weight: 1
        $x_1_10 = "expand 32-byte kexpand 32-byte k" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_MDK_2147778008_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MDK!MTB"
        threat_id = "2147778008"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8d 15 89 0b 05 00 48 8b c8 48 8b f0 e8 [0-4] 48 8d 15 67 0b 05 00 48 8b ce 48 8b e8 e8 [0-4] 48 8d 15 45 0b 05 00 48 8b ce 48 8b d8 e8 [0-4] 48 8d 15 23 0b 05 00 48 8b ce 48 8b f8 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 44 0a f8 4c 8b 54 0a f0 48 83 e9 [0-1] 48 89 41 18 4c 89 51 10 48 8b 44 0a 08 4c 8b 14 0a 49 ff c9 48 89 41 08 4c 89 11 75 d5}  //weight: 1, accuracy: Low
        $x_1_3 = {0f b6 02 48 ff c1 48 ff ca 48 3b cf 88 44 31 [0-1] 7c ee}  //weight: 1, accuracy: Low
        $x_1_4 = {48 8d 15 17 0d 05 00 48 8b c8 48 8b d8 e8 [0-4] 48 8d 15 f5 0c 05 00 48 8b cb 48 8b f0 e8 [0-4] 48 8d 15 d3 0c 05 00 48 8b cb 4c 8b f0 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win64_CobaltStrike_CK_2147779926_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CK!MTB"
        threat_id = "2147779926"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 8b d0 48 8d 49 ?? 83 e2 ?? 49 ff c0 0f b6 04 3a 32 44 0b ?? 88 41 ?? 49 83 e9 ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CK_2147779926_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CK!MTB"
        threat_id = "2147779926"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {30 c1 41 88 4d 0f 88 83 ?? ?? 00 00 49 83 c5 10 4d 39 f5 74}  //weight: 2, accuracy: Low
        $x_2_2 = {0f b6 4c 04 1f 41 30 4c 07 ff 0f b6 4c 04 20 41 30 0c 07 48 83 c0 10 48 3d 8f 00 00 00 0f 85}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_MEK_2147779944_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MEK!MTB"
        threat_id = "2147779944"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tps://122.228.7.225/admin?file=" ascii //weight: 1
        $x_1_2 = "Cache Session" ascii //weight: 1
        $x_1_3 = "NetworkListManager" ascii //weight: 1
        $x_1_4 = "Kerberos" ascii //weight: 1
        $x_1_5 = "122.193.130.74" ascii //weight: 1
        $x_1_6 = "netprofm,netman" ascii //weight: 1
        $x_1_7 = "epmapper" ascii //weight: 1
        $x_1_8 = "Security=Impersonation Dynamic False" ascii //weight: 1
        $x_1_9 = "121.207.229.145" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule Trojan_Win64_CobaltStrike_MFK_2147779945_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MFK!MTB"
        threat_id = "2147779945"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c9 53 0f a2 8b f3 5b 8d 5d dc}  //weight: 1, accuracy: High
        $x_10_2 = {8b c1 33 d2 f7 f6 8a 44 15 [0-1] 30 04 39 41 81 f9 [0-2] 00 00 7c}  //weight: 10, accuracy: Low
        $x_10_3 = {6a 40 68 00 30 00 00 68 [0-2] 00 00 6a 00 ff 15 [0-4] 85 c0 74 0e 8b f7 b9 [0-2] 00 00 8b f8 f3 a5 a4 ff d0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_CobaltStrike_MGK_2147779989_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MGK!MTB"
        threat_id = "2147779989"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 8b c1 0f a2 89 04 24 b8 [0-4] 89 4c 24 08 23 c8 89 5c 24 04 89 54 24 0c 3b c8 75 2c}  //weight: 1, accuracy: Low
        $x_1_2 = {b9 10 27 00 00 ff 15 15 fb 00 00 eb f3}  //weight: 1, accuracy: High
        $x_1_3 = {8b 44 24 08 ff c0 89 44 24 08 8b 44 24 10 8b 4c 24 08 99 f7 f9 89 44 24 10 8b 44 24 10 83 e8 [0-1] 89 44 24 10 8b 44 24 08 83 c0 [0-1] 89 44 24 08 8b 44 24 08 83 f8 [0-1] 7c c8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_MBK_2147780033_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MBK!MTB"
        threat_id = "2147780033"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 e2 03 8a 54 15 [0-1] 41 32 14 04 88 14 03 48 ff c0 39 f8 89 c2 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_E_2147782693_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.E!ibt"
        threat_id = "2147782693"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "fA]Z" ascii //weight: 1
        $x_1_2 = "YG@JG\\" ascii //weight: 1
        $x_1_3 = "]W]@OZGXK" ascii //weight: 1
        $x_1_4 = "|ZB{]K\\zF\\KOJ}ZO\\Z" ascii //weight: 1
        $x_1_5 = {4d 5a 41 52 55 48 89 e5}  //weight: 1, accuracy: High
        $x_1_6 = {8e 4e 0e ec 74 ?? 81 7c ?? ?? aa fc 0d 7c 74 ?? 81 7c ?? ?? 54 ca af 91 74 ?? 81 7c ?? ?? 1b c6 46 79 74 ?? 81 7c ?? ?? fc a4 53 07 74 ?? 81 7c ?? ?? 04 49 32 d3 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_D_2147784792_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.D!MTB"
        threat_id = "2147784792"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {48 89 4c 24 08 48 83 ec 68 65 48 8b 04 25 60 00 00 00 48 89 44 24 08 48 8b 44 24 08 48 8b 40 18 48 89 44 24 08 48 8b 44 24 08 48 8b 40 20 48 89 44 24 28 48}  //weight: 10, accuracy: High
        $x_10_2 = {48 8b 44 24 50 48 63 40 3c 48 8b 4c 24 50 48 03 c8 48 8b c1 48 89 44 24 38 48 8b 44 24 38 0f b7 40 16 25 00 80 00 00 3d 00 80 00 00 75 0a c7 44 24 48 40}  //weight: 10, accuracy: High
        $x_3_3 = {4d 5a 41 52 55 48 89 e5 48 81 ec 20}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_D_2147784792_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.D!MTB"
        threat_id = "2147784792"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 89 c9 89 c8 41 f7 ea c1 fa 04 89 c8 c1 f8 1f 29 c2 89 d0 c1 e0 06 8d 14 50 41 29 d1 4d 63 c9 48 8b 05 ?? ?? ?? ?? 42 0f b6 04 08 32 44 0c 60 41 88 04 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_AS_2147786451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.AS!MTB"
        threat_id = "2147786451"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {45 0f af d1 41 01 d2 4d 63 d2 42 8a 04 11 41 30 04 37 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_AS_2147786451_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.AS!MTB"
        threat_id = "2147786451"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 01 c0 31 ca 88 10 48 83 45 ?? 01 48 8b 45 ?? 48 3b 45 ?? 73 ?? 48 8b 55 ?? 48 8b 45 ?? 48 01 d0 0f b6 08 48 8b 45 ?? ba 00 00 00 00 48 f7 75 ?? 48 8b 45 ?? 48 01 d0 0f b6 10 4c 8b 45 10 48 8b 45}  //weight: 1, accuracy: Low
        $x_1_2 = {48 01 d0 44 89 c2 31 ca 88 10 83 45 ?? 01 83 45 ?? 01 8b 45 ?? 48 98 48 3b 45 ?? 8b 45 ?? 48 98 48 3b 45 ?? 72 ?? c7 45 ?? 00 00 00 00 8b 45 ?? 48 63 d0 48 8b 45 ?? 48 01 d0 44 0f b6 00 8b 45 ?? 48 63 d0 48 8b 45 ?? 48 01 d0 0f b6 08 8b 45 ?? 48 63 d0 48 8b 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_CobaltStrike_AS_2147786451_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.AS!MTB"
        threat_id = "2147786451"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "CFy92ROzKls\\ro\\HwtAF.pdb" ascii //weight: 3
        $x_3_2 = "AppPolicyGetProcessTerminationMethod" ascii //weight: 3
        $x_3_3 = "LocaleNameToLCID" ascii //weight: 3
        $x_3_4 = "IsDebuggerPresent" ascii //weight: 3
        $x_3_5 = "GetStartupInfoW" ascii //weight: 3
        $x_3_6 = "InitializeCriticalSectionAndSpinCount" ascii //weight: 3
        $x_3_7 = "RtlLookupFunctionEntry" ascii //weight: 3
        $x_3_8 = "r8BsHuPe56l\\ilYp\\i12tW5S7m3" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_FOC_2147795724_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.FOC!MTB"
        threat_id = "2147795724"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "muuuutex" ascii //weight: 1
        $x_1_2 = {48 c7 c1 05 00 00 00 8a 10 80 f2 55 88 10 48 ff c0 e2 f4 48 b8 ?? ?? ?? ?? ?? 00 00 00 48 c7 c1 19 00 00 00 8a 10 80 f2 55 88 10 48 ff c0 e2 f4 48 b8 ?? ?? ?? ?? ?? 00 00 00 48 c7 c1 14 00 00 00 8a 10 80 f2 55 88 10 48 ff c0 e2 f4 48 b8 ?? ?? ?? ?? ?? 00 00 00 48 c7 c1 06 00 00 00 8a 10 80 f2 55 88 10 48 ff c0 e2 f4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_PB_2147806105_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.PB!MTB"
        threat_id = "2147806105"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c8 f7 ea c1 fa ?? 89 c8 c1 f8 ?? 29 c2 89 d0 6b c0 ?? 29 c1 89 c8 48 98 4c 01 d0 0f b6 00 44 31 c8 41 88 00 83 85 1c 05 00 00 ?? 8b 85 1c 05 00 00 3b 85 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_PB_2147806105_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.PB!MTB"
        threat_id = "2147806105"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 d0 f7 d0 25 ?? ?? ?? ?? 81 e2 ?? ?? ?? ?? 09 c2 81 f2 ?? ?? ?? ?? 89 15}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 09 89 ca f6 d2 89 c3 f6 d3 41 89 d0 41 80 e0 ?? 80 e1 ?? 44 08 c1 08 da 80 e3 ?? 24 ?? 08 d8 30 c8 f6 d2 08 c2 48 8b 45 ?? 88 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_CobaltStrike_AI_2147807869_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.AI!MTB"
        threat_id = "2147807869"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {0f b6 c8 44 02 d9 44 02 df 41 0f b6 cb 8a 44 8d 08 41 30 06 8b 44 8d 08 49 ff c6 31 44 95 08 42 8b 44 a5 08 41 8d 0c 00 42 31 4c 95 08 49 ff cf 0f}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_AI_2147807869_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.AI!MTB"
        threat_id = "2147807869"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 3c 08 8b 84 24 ?? ?? ?? ?? 99 b9 ?? ?? ?? ?? f7 f9 48 63 ca 48 8b 44 24 ?? 0f b6 04 08 8b d7 33 d0 48 63 8c 24 ?? ?? ?? ?? 48 8b 44 24 ?? 88 14 08 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_AI_2147807869_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.AI!MTB"
        threat_id = "2147807869"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 39 44 24 ?? 44 89 c0 76 ?? 99 f7 f9 48 8d 05 ?? ?? ?? ?? 48 63 d2 8a 14 10 48 8b 84 24 ?? ?? ?? ?? 42 32 14 00 42 88 14 06 49 ff c0 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {65 48 8b 04 25 60 00 00 00 48 8b 40 18 48 89 cf 48 8b 58 10 48 89 de 48 8b 4b 60 48 89 fa}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_AJ_2147808528_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.AJ!MTB"
        threat_id = "2147808528"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b c2 89 44 24 ?? 8b 04 24 48 8b 4c 24 ?? 0f b6 04 01 8b 4c 24 ?? 48 8b 54 24 ?? 0f b6 0c 0a 33 c1 8b 0c 24 48 8b 54 24 ?? 88 04 0a 8b 04 24 48 8b 4c 24 ?? 0f b6 04 01 03 44 24 ?? 8b 0c 24 48 8b 54 24 ?? 88 04 0a eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_AJ_2147808528_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.AJ!MTB"
        threat_id = "2147808528"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {4c 03 c0 41 02 10 88 54 24 ?? 41 0f b6 08 0f b6 c2 48 8d 54 24 ?? 48 03 d0 0f b6 02 41 88 00 88 0a 0f b6 54 24 ?? 44 0f b6 44 24 ?? 0f b6 4c 14 ?? 42 02 4c 04 ?? 0f b6 c1 0f b6 4c 04 ?? 42 32 4c 0b 0f 41 88 49 ff 48 83 ef 01 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_AJ_2147808528_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.AJ!MTB"
        threat_id = "2147808528"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {41 0f af c0 89 43 ?? 48 8b 83 ?? ?? ?? ?? 88 14 01 48 63 8b ?? ?? ?? ?? 8d 41 ?? 89 83 ?? ?? ?? ?? 8b 43 ?? 2d ?? ?? ?? ?? 0f af 43 ?? 89 43 ?? 48 8b 83 ?? ?? ?? ?? 44 88 4c 01 ?? b8 ?? ?? ?? ?? 2b 83 ?? ?? ?? ?? ff 83 ?? ?? ?? ?? 89 83 ?? ?? ?? ?? 49 81 fb ?? ?? ?? ?? 0f 8c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_AN_2147808530_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.AN!MTB"
        threat_id = "2147808530"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4d 63 c1 b8 ?? ?? ?? ?? 45 88 0c 18 41 f7 e1 41 8b c1 c1 ea ?? 41 83 c1 ?? 6b d2 ?? 2b c2 44 3b ce 42 0f b6 04 10 43 88 04 18 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_AO_2147808749_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.AO!MTB"
        threat_id = "2147808749"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 c2 89 d0 83 e0 01 02 04 11 83 e8 03 49 39 d0 88 04 11 48 8d 42 01 48 89 c2 89 d0 83 e0 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_AO_2147808749_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.AO!MTB"
        threat_id = "2147808749"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff c0 89 84 24 ?? ?? ?? ?? 48 63 84 24 ?? ?? ?? ?? 48 83 f8 ?? 73 ?? 48 63 84 24 ?? ?? ?? ?? 0f b6 84 04 ?? ?? ?? ?? 83 e8 ?? 48 63 8c 24 ?? ?? ?? ?? 88 84 0c ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_AL_2147809017_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.AL!MTB"
        threat_id = "2147809017"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 29 c0 8b 05 ?? ?? ?? ?? 41 29 c0 44 89 c0 4c 63 c0 48 8b 45 ?? 4c 01 c0 0f b6 00 31 c8 88 02 83 45 ?? ?? 8b 45 ?? 3b 45 ?? 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_AL_2147809017_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.AL!MTB"
        threat_id = "2147809017"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 5c 24 10 48 89 74 24 18 57 48 83 ec 10 33 c0 33 c9 0f a2 44 8b c1 45 33 db 44 8b ?? 41 81 f0 6e 74 65 6c 41 81 ?? ?? ?? ?? ?? 44 8b ?? 8b f0 33 c9 41 8d 43 01 45 0b}  //weight: 1, accuracy: Low
        $x_1_2 = {0f a2 41 81 ?? ?? ?? ?? ?? 89 04 24 45 0b ?? 89 5c 24 04 8b f9 89 4c 24 08 89 54 24 0c 75 ?? 48 83 0d ?? ?? ?? ?? ?? 25 f0 3f ff 0f}  //weight: 1, accuracy: Low
        $x_1_3 = {ff ff ff ff 72 62 00 00 00 00 00 00 [0-48] 2e 62 69 6e}  //weight: 1, accuracy: Low
        $x_1_4 = "VirtualAlloc" ascii //weight: 1
        $x_1_5 = "CreateThread" ascii //weight: 1
        $x_1_6 = "fopen" ascii //weight: 1
        $x_1_7 = "fseek" ascii //weight: 1
        $x_1_8 = "ftell" ascii //weight: 1
        $x_1_9 = "malloc" ascii //weight: 1
        $x_1_10 = "fread" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_AR_2147809018_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.AR!MTB"
        threat_id = "2147809018"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 df b3 ff 8b 44 24 ?? 20 c7 30 d8 22 44 24 ?? 08 f8 88 44 14 ?? 42 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_AT_2147809077_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.AT!MTB"
        threat_id = "2147809077"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 c0 80 84 04 ?? ?? ?? ?? ?? 48 ff c0 48 83 f8 ?? 75 20 00 c6 84 24}  //weight: 1, accuracy: Low
        $x_1_2 = {44 30 c3 44 20 cb 44 20 d6 40 08 de 40 30 d6 40 88 74 04 ?? 49 ff c3 48 ff c0 48 83 f8 ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_AU_2147809332_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.AU!MTB"
        threat_id = "2147809332"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 04 24 0f b6 4c 24 ?? 48 8b 54 24 ?? 0f be 04 02 33 c1 8b 0c 24 48 8b 54 24 ?? 88 04 0a eb}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_PC_2147809473_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.PC!MTB"
        threat_id = "2147809473"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 33 db 41 ba 13 9d d9 35 48 8b c2 66 0f 1f 44 00 00 0f b7 00 41 8b ca c1 c9 08 41 ff c3 03 c8 41 8b c3 48 03 c2 44 33 d1 80 38 00 75 ?? 4a 8d 0c [0-6] 41 ff c0 46 89 54 39 ?? 0f b7 44 5d ?? 41 8b ?? 86 42 89 44 39}  //weight: 1, accuracy: Low
        $x_1_2 = "fuck sandbox" ascii //weight: 1
        $x_1_3 = "\\Bypass_AV.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CE_2147809475_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CE!MTB"
        threat_id = "2147809475"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {48 63 c2 0f b6 44 04 ?? 43 32 44 11}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CE_2147809475_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CE!MTB"
        threat_id = "2147809475"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b ca 48 ff c2 83 e1 ?? 42 8a 0c 31 32 0c 2b 88 0b 48 ff c3 48 ff c8 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CE_2147809475_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CE!MTB"
        threat_id = "2147809475"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 98 4c 89 ca 48 29 c2 48 8b 45 ?? 48 01 d0 0f b6 10 8b 45 ?? 01 d0 44 31 c0 88 01 83 45}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CE_2147809475_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CE!MTB"
        threat_id = "2147809475"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 8b 02 49 83 c1 20 49 83 c2 20 48 ff c9 41 89 41 e0 41 8b 42 e4 41 89 41 e4 41 8b 42 e8 41 89 41 e8 41 8b 42 ec 41 89 41 ec 41 8b 42 f0 41 89 41 f0 41 8b 42 f4 41 89 41 f4 41 8b 42 f8 41 89 41 f8 41 8b 42 fc 41 89 41 fc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CE_2147809475_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CE!MTB"
        threat_id = "2147809475"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {31 c6 89 f1 48 8b 15 ?? ?? ?? 00 8b 45 fc 48 98 48 01 d0 89 ca 88 10 83 45 fc 01 eb}  //weight: 2, accuracy: Low
        $x_2_2 = {89 45 fc 8b 45 fc 41 b9 04 00 00 00 41 b8 00 30 00 00 48 89 c2 b9 00 00 00 00 48 8b 05 ?? ?? ?? 00 ff d0 48 89 45}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CE_2147809475_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CE!MTB"
        threat_id = "2147809475"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0f b6 07 4c 8d 44 24 68 48 8b 54 24 60 34 45 4c 63 f6 41 b9 01 00 00 00 49 03 d6 88 44 24 68 49 8b cf 4c 89 64 24 20}  //weight: 10, accuracy: High
        $x_3_2 = "Bypass_AV.pdb" ascii //weight: 3
        $x_3_3 = "fuck sandbox" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_AV_2147809812_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.AV!MTB"
        threat_id = "2147809812"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {f6 0f b6 14 31 01 d0 31 d2 f7 35 ?? ?? ?? ?? 29 fa 29 fa 48 63 d2 8a 04 11 43 30 04 17 e9}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_AY_2147809813_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.AY!MTB"
        threat_id = "2147809813"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 8b 45 18 48 01 d0 0f b6 00 88 01 83 45 ?? ?? 8b 55 ?? 8b 05 ?? ?? ?? ?? 39 c2 0f 82}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_PI_2147809859_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.PI!MTB"
        threat_id = "2147809859"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 01 c2 4c 63 c2 48 8b 55 10 4c 01 c2 0f b6 12 31 ca 88 10 83 45 f4 01 8b 45 f4 3b 45 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_PI_2147809859_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.PI!MTB"
        threat_id = "2147809859"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 04 17 30 04 0e 8d 41 ?? 99 f7 fb 0f b6 04 17 30 44 0e ?? 48 8d 41 ?? 44 39 c8 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_PI_2147809859_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.PI!MTB"
        threat_id = "2147809859"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b ca 0f af c8 41 8b ?? 03 c1 48 63 c8 48 8b 44 24 ?? 0f b6 0c 08 48 8b 44 24 ?? 42 0f b6 34 ?? 33 f1 8b 4c 24 ?? 8b 44 24 ?? 03 c1}  //weight: 2, accuracy: Low
        $x_1_2 = {41 2b c3 2b c3 2b c7 8b c8 48 8b 44 24 ?? 40 88 34 08 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_PI_2147809859_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.PI!MTB"
        threat_id = "2147809859"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Balas e Tiros" ascii //weight: 1
        $x_1_2 = "InternetReadFile(...)" ascii //weight: 1
        $x_1_3 = "HttpSendRequestA(...)" ascii //weight: 1
        $x_1_4 = "/htEp" ascii //weight: 1
        $x_1_5 = "oshi.at" ascii //weight: 1
        $x_1_6 = "UserInitMprLogonScript" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_AW_2147809920_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.AW!MTB"
        threat_id = "2147809920"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 63 c8 41 ff c0 48 8b 44 24 ?? 42 0f b6 14 11 41 32 14 39 41 88 14 01 49 ff c1 49 63 c0 48 3b 45 88 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_NWOD_2147810180_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.NWOD!MTB"
        threat_id = "2147810180"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 c6 43 80 fc 41 c6 43 81 d1 41 c6 43 82 d6 41 c6 43 83 17 41 c6 43 84 c4 41 c6 43 85 97 41 c6 43 86 62 41 c6 43 87 a0 41 c6 43 88 3b 41 c6 43 89 2e 41 c6 43 8a c7 41 c6 43 8b 5a 41 c6 43 8c 72 41 c6 43 8d 40 41 c6 43 8e 33 41 c6 43 8f 01 41 c6 43 90 1c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_NWO_2147810181_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.NWO!MTB"
        threat_id = "2147810181"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 b4 05 b0 fc ff ff 1a 40 3d}  //weight: 1, accuracy: High
        $x_1_2 = "StartUserModeBrowserInjection" ascii //weight: 1
        $x_1_3 = "StopUserModeBrowserInjection" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_NWOE_2147810590_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.NWOE!MTB"
        threat_id = "2147810590"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 ff c9 41 8b 34 88 48 01 d6 4d 31 c9 48 31 c0 ac 41 c1 c9 0d 41 01 c1 38 e0}  //weight: 1, accuracy: High
        $x_1_2 = "NtAllocateVirtualMemory" ascii //weight: 1
        $x_1_3 = "SystemUpdate" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_AX_2147810766_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.AX!MTB"
        threat_id = "2147810766"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {41 0f b6 44 1d ?? 30 04 3e 83 44 24 ?? ?? 81 7c 24 ?? ?? ?? ?? ?? 0f 85}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_AX_2147810766_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.AX!MTB"
        threat_id = "2147810766"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Beacon_set_Memory_attributes" ascii //weight: 1
        $x_1_2 = "Nc4883e4N0e8c8000000415141505251564831d265488b5260488b5218488b522" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_BA_2147810767_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.BA!MTB"
        threat_id = "2147810767"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 89 c2 83 e2 03 8a 54 15 00 32 14 07 88 14 03 48 ff c0 eb}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_BB_2147811090_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.BB!MTB"
        threat_id = "2147811090"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 89 c2 83 e2 ?? 41 8a 14 14 32 54 05 ?? 88 14 03 48 ff c0 eb 19 00 39 f8 7d 16}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_BB_2147811090_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.BB!MTB"
        threat_id = "2147811090"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 29 c3 45 01 d9 45 01 cc 4d 63 e4 42 32 0c 20 48 8b 44 24 ?? 88 0c 10 48 8b 44 24 ?? 48 39 44 24 ?? 48 8d 58 01 b8 ?? ?? ?? ?? 44 8b 0d ?? ?? ?? ?? 44 8b 05 ?? ?? ?? ?? 41 f7 ef}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_BD_2147811662_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.BD!MTB"
        threat_id = "2147811662"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 d2 0f b7 ?? 33 d2 66 2b 05 ?? ?? ?? ?? 66 f7 35 ?? ?? ?? ?? 88 06 46 33 d2 43 33 d2 83 c1 02 4f 8b d7 85 d2 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_BF_2147811998_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.BF!MTB"
        threat_id = "2147811998"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {44 8a 4c 04 ?? 8b 74 24 ?? 44 89 c9 44 30 c1 40 20 f1 44 30 c6 44 20 ce 40 08 ce 40 88 74 04 ?? 49 ff c2 48 ff c0 48 83 f8 ?? 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_BF_2147811998_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.BF!MTB"
        threat_id = "2147811998"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {44 0f af 43 5c 48 8b 83 b0 00 00 00 41 8b d0 c1 ea 08 88 14 01 ff 43 60 48 63 4b 60 48 8b 83 b0 00 00 00 44 88 04 01 ff 43 60 8b 43 20 8b 4b 3c 83 c0 a6 03 c8 8b 83 98 00 00 00 31 4b}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_AH_2147812027_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.AH!MTB"
        threat_id = "2147812027"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {30 10 83 c2 01 48 83 c0 01 0f b6 d2 48 39 c8 75 ef}  //weight: 1, accuracy: High
        $x_1_2 = "XQC@VERkz^TEXDXQCk`^YSX@DktBEERYCaRED^XYkeBY7" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_AH_2147812027_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.AH!MTB"
        threat_id = "2147812027"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c1 2b 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 03 c1 2b 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 03 c1 2b 05 ?? ?? ?? ?? 48 63 d0 48 8b 4c 24 ?? 48 8b 44 24 ?? 42 0f b6 04 00 88 04 11 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_AH_2147812027_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.AH!MTB"
        threat_id = "2147812027"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {03 c8 48 8b 05 ?? ?? ?? 00 31 0d ?? ?? ?? 00 49 63 48 ?? 41 8b d1 c1 ea 10 88 14 01}  //weight: 2, accuracy: Low
        $x_2_2 = {48 8b 44 24 ?? 80 e9 ?? 32 0d ?? ?? ?? 00 41 88 0c 02 41 0f b7 44 5e}  //weight: 2, accuracy: Low
        $x_1_3 = {44 03 c9 8b 53 ?? 33 c9 41 81 f0 00 30 00 00 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_AH_2147812027_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.AH!MTB"
        threat_id = "2147812027"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 89 c2 49 89 f0 e8 ?? ?? ?? ?? 48 8d 15 ?? ?? ?? ?? 48 89 f9 e8 ?? ?? ?? ?? 48 c7 44 24 20 ?? ?? ?? ?? 41 b9 ?? ?? ?? ?? 48 c7 c1}  //weight: 5, accuracy: Low
        $x_1_2 = "EtwEventWriteFull" ascii //weight: 1
        $x_1_3 = "notepad.exe" ascii //weight: 1
        $x_1_4 = "WriteProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_AH_2147812027_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.AH!MTB"
        threat_id = "2147812027"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 14 01 ff 43 ?? 8b 83 ?? ?? ?? ?? 33 83 ?? ?? ?? ?? 35 ?? ?? ?? ?? 89 83 ?? ?? ?? ?? 8b 83 ?? ?? ?? ?? 48 63 4b ?? 2d ?? ?? ?? ?? 31 43 ?? 48 8b 43 ?? 44 88 04 01 ff 43 ?? 8b 43 ?? 33 83 ?? ?? ?? ?? 2d ?? ?? ?? ?? 31 43 ?? 8b 43 ?? 2b 83 ?? ?? ?? ?? 2d ?? ?? ?? ?? 01 83 ?? ?? ?? ?? 49 81 f9 ?? ?? ?? ?? 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_PD_2147812875_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.PD!MTB"
        threat_id = "2147812875"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "%02d/%02d/%02d %02d:%02d:%02d" ascii //weight: 1
        $x_1_2 = "%s as %s\\%s: %d" ascii //weight: 1
        $x_1_3 = "Started service %s on %s" ascii //weight: 1
        $x_1_4 = "beacon.dll" ascii //weight: 1
        $x_1_5 = "beacon.x64.dll" ascii //weight: 1
        $x_1_6 = "ReflectiveLoader" ascii //weight: 1
        $x_1_7 = "%s (admin)" ascii //weight: 1
        $x_1_8 = "Updater.dll" ascii //weight: 1
        $x_1_9 = "LibTomMath" ascii //weight: 1
        $x_1_10 = "Content-Type: application/octet-stream" ascii //weight: 1
        $x_1_11 = "rijndael" ascii //weight: 1
        $x_1_12 = {2e 2f 2e 2f 2e 2c [0-4] 2e 2c 2e 2f}  //weight: 1, accuracy: Low
        $x_1_13 = {69 68 69 68 69 6b [0-4] 69 6b 69 68}  //weight: 1, accuracy: Low
        $x_1_14 = {70 6f 73 74 00 63 64 6e 2e 25 78 25 78 2e 25 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule Trojan_Win64_CobaltStrike_AB_2147813010_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.AB!MTB"
        threat_id = "2147813010"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {ff d7 48 89 d8 83 e0 07 8a 44 05 00 30 04 ?? 48 ff c3 48 83 fb 40 75 e8}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_AB_2147813010_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.AB!MTB"
        threat_id = "2147813010"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Go build ID:" ascii //weight: 1
        $x_1_2 = "TcyAkqh4oJXgV3WYyL4KEfCMk9W8oJCpmx1bo+jVgKY=" ascii //weight: 1
        $x_1_3 = "QJMbhCSEH5rAuRxh+CtW96g0Or0Fxa9IKr4uc=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_AB_2147813010_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.AB!MTB"
        threat_id = "2147813010"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f3 0f 6f 41 ?? 48 8d 49 ?? 66 0f 6f ca 66 0f ef c8 f3 0f 7f 49 ?? f3 0f 6f 41 ?? 66 0f ef c2 f3 0f 7f 41 ?? f3 0f 6f 49 ?? 66 0f ef ca f3 0f 7f 49 ?? 66 0f 6f ca f3 0f 6f 41 ?? 66 0f ef c8 f3 0f 7f 49 ?? 49 83 ee}  //weight: 1, accuracy: Low
        $x_1_2 = {41 8b c1 4d 8d 40 01 99 41 ff c1 f7 ff 48 63 c2 0f b6 4c 04 ?? 41 30 48 ff 49 83 ea 01 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_AB_2147813010_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.AB!MTB"
        threat_id = "2147813010"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e8 8b f1 ff ff ba 6f 80 e5 67 48 8b cb 48 89 05 04 26 03 00 e8 77 f1 ff ff ba eb 62 6b c2 48 8b ce 48 89 05 10 26 03 00}  //weight: 1, accuracy: High
        $x_1_2 = {4c 2b d0 8b c5 41 0f af c0 4d 69 d2 d0 00 00 00 41 0f af c0 48 98 48 2b d8 41 8b c1}  //weight: 1, accuracy: High
        $x_1_3 = {41 0f af c4 48 63 c8 49 63 c5 48 2b d9 48 2b d8 49 63 c1 48 2b d8 49 2b d8 49 03 df 48 03 df 48 8d 04 5b 48 c1 e0 06 4b 03}  //weight: 1, accuracy: High
        $x_1_4 = {f7 d8 48 98 4c 03 c0 49 8d 44 24 03 49 0f af c6 4c 03 c0 41 8b c5 f7 d8 48 63 c8 8b 05 eb 0c 03 00 f7 d8}  //weight: 1, accuracy: High
        $x_1_5 = {44 89 64 24 28 48 8b de c7 44 24 20 40 00 00 00 41 ff d2 eb 1a 41 b9 40 00 00 00 41 b8 00 30 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win64_CobaltStrike_HA_2147813079_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.HA!MTB"
        threat_id = "2147813079"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 7c 24 04 8e 4e 0e ec 74 36 81 7c 24 04 aa fc 0d 7c 74 2c 81 7c 24 04 54 ca af 91 74 22 81 7c 24 04 1b c6 46 79 74 18 81 7c 24 04 fc a4 53 07 74 0e 81 7c 24 04 04 49 32 d3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_DE_2147813449_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.DE!MTB"
        threat_id = "2147813449"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 4c 05 e0 4c 8d 48 01 41 32 48 ff 48 63 c2 ff c2 48 03 45 c0 88 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_DE_2147813449_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.DE!MTB"
        threat_id = "2147813449"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 4c 24 28 0f b6 04 01 89 44 24 30 48 63 4c 24 20 33 d2 48 8b c1 b9 ?? ?? ?? ?? 48 f7 f1 48 8b c2 8b 4c 24 30 33 4c 84 40 8b c1 48 63 4c 24 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_DE_2147813449_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.DE!MTB"
        threat_id = "2147813449"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 04 24 0f b6 4c 24 30 48 8b 54 24 20 0f be 04 02 33 c1 8b 0c 24 48 8b 54 24 20 88 04 0a}  //weight: 1, accuracy: High
        $x_1_2 = {89 ca 83 e2 03 41 0f b6 14 17 32 14 0f 88 14 0b 8d 51 01 83 e2 03 41 0f b6 14 17 32 54 0f 01 88 54 0b 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_CobaltStrike_BL_2147814223_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.BL!MTB"
        threat_id = "2147814223"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 85 f6 74 26 41 8a 44 2c 10 48 8b bc 24 88 00 00 00 32 84 33 e8 03 00 00 48 ff c6 83 e6 0f 88 44 2f 10 48 ff c5 e9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_BL_2147814223_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.BL!MTB"
        threat_id = "2147814223"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 8b c6 48 ff c6 48 c1 ea ?? 48 69 d2 ?? ?? ?? ?? 48 2b c2 0f b6 44 04 ?? 41 30 43 ?? 48 ff c9 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_BL_2147814223_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.BL!MTB"
        threat_id = "2147814223"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 4c 24 ?? 39 c3 7e ?? 48 89 c2 83 e2 ?? 8a 14 17 32 14 06 88 14 01 48 ff c0 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {41 89 d0 42 80 3c 01 ?? 74 ?? 41 89 c1 46 0f b7 04 01 ff c2 41 c1 c9 ?? 45 01 c8 44 31 c0 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_CobaltStrike_BL_2147814223_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.BL!MTB"
        threat_id = "2147814223"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 0f b7 01 [0-4] 66 2b ?? ?? ?? ?? ?? [0-4] 66 f7 [0-9] 88 06 [0-4] 46 [0-4] 43 [0-4] 83 c1 02}  //weight: 1, accuracy: Low
        $x_10_2 = {33 d2 0f b7 01 [0-4] 66 2b ?? ?? ?? ?? ?? [0-4] 66 f7 [0-9] 88 06 [0-4] 46 [0-4] 43 [0-4] 83 c1 02 [0-4] 4f 8b d7 85 fa 75}  //weight: 10, accuracy: Low
        $x_1_3 = "AUTO" ascii //weight: 1
        $x_1_4 = "!This is a Windows NT windowed dynamic link library" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_CobaltStrike_DED_2147814377_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.DED!MTB"
        threat_id = "2147814377"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 0f 45 c8 42 0f b6 04 19 30 42 ff 33 c0 49 83 f8 0c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_DECI_2147814378_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.DECI!MTB"
        threat_id = "2147814378"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 04 24 ff c0 89 04 24 8b 44 24 28 39 04 24 73 20 8b 04 24 0f b6 4c 24 30 48 8b 54 24 20 0f be 04 02 33 c1 8b 0c 24 48 8b 54 24 20 88 04 0a}  //weight: 1, accuracy: High
        $x_1_2 = {48 8b d3 48 8b ce 48 2b c3 48 d1 f8 4c 8b c0 e8 7c 10 00 00 48 8b ce ff 15 5b 16 00 00 48 8b f0 48 8b cb ff 15 4f 16 00 00 48 8b d8 0f b7 38 66}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_CobaltStrike_ZEK_2147814379_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.ZEK!MTB"
        threat_id = "2147814379"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 ff c3 49 ff c1 41 f7 e3 2b ca 41 8b c3 41 ff c3 d1 e9 03 ca c1 e9 06 6b c9 75 2b c1 44 3b df 42 0f b6 04 00 88 43 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_YEK_2147814380_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.YEK!MTB"
        threat_id = "2147814380"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 94 24 40 03 00 00 0f b6 0c 11 8b c1 99 f7 bc 24 80 06 00 00 8b c2 03 44 24 20 8b 8c 24 d4 04 00 00 03 c1 89 44 24 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_ZEL_2147814381_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.ZEL!MTB"
        threat_id = "2147814381"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 33 c4 48 89 85 80 00 00 00 48 8b f2 48 8b f9 45 33 ed 44 89 6c 24 20 48 8b 49 28 4c 8b 77 38 49 c1 e6 06 4c 03 f1 49 c1 e6 03 48 8b 57 30 48 3b ca}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_DY_2147814630_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.DY!MTB"
        threat_id = "2147814630"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 04 1f 30 03 48 ff c3 48 83 e9 01 75 ?? 48 83 ef ?? 0f 29 84 24 ?? ?? ?? ?? 48 83 ee 01 75}  //weight: 1, accuracy: Low
        $x_1_2 = {41 0f b6 84 38 ?? ?? ?? ?? 41 30 00 49 ff c0 48 83 e9 01 75 ?? 49 83 e9 01 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_DY_2147814630_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.DY!MTB"
        threat_id = "2147814630"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 ca 03 c1 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 2b c1 2b 05 ?? ?? ?? ?? 48 63 c8 48 8b 84 24 ?? ?? ?? ?? 0f b6 0c 08 48 8b 84 24 ?? ?? ?? ?? 42 0f b6 04 00 33 c1 89 44 24 14 8b 05 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 89 44 24 18 8b 05 ?? ?? ?? ?? 0f af 05}  //weight: 1, accuracy: Low
        $x_1_2 = "O#37HW^$L(n+GwVeG(mHfMu!(YQ5y)n6yB(Ej_naHAUd>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_CobaltStrike_DZ_2147814631_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.DZ!MTB"
        threat_id = "2147814631"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 c0 0f b6 4c 24 ?? 33 c1 0f b7 4c 24 ?? 48 8b 54 24 ?? 88 04 0a 0f b7 44 24 ?? 66 ff c0 66 89 44 24 ?? 0f b7 44 24 ?? 0f b7 4c 24 ?? 3b c1 7d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_DZ_2147814631_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.DZ!MTB"
        threat_id = "2147814631"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "DllMain" ascii //weight: 10
        $x_10_2 = "DllRegisterServer" ascii //weight: 10
        $x_1_3 = "hovitdz.dll" ascii //weight: 1
        $x_1_4 = "bivyyycpsulxgygg" ascii //weight: 1
        $x_1_5 = "dhoqwlwdlcap" ascii //weight: 1
        $x_1_6 = "djerzrgfgshl" ascii //weight: 1
        $x_1_7 = "dnqficfiirwdy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CMP_2147814739_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CMP!MTB"
        threat_id = "2147814739"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 44 85 a0 09 c1 89 ca 8b 85 a4 01 00 00 48 98 48 8d 48 02 48 8b 85 98 01 00 00 48 01 c8 88 10 83 85 a4 01 00 00 03 83 85 a8 01 00 00 04 8b 85 a0 01 00 00 83 e8 02 39 85 a8 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CMP_2147814739_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CMP!MTB"
        threat_id = "2147814739"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b7 44 24 24 83 f8 41 7c 17 0f b7 44 24 24 83 f8 5a 7f 0d 0f b7 44 24 24 83 c0 20 66 89 44 24 24 0f b7 44 24 28 83 f8 41 7c 17 0f b7 44 24 28 83 f8 5a 7f 0d 0f b7 44 24 28 83 c0 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_EC_2147814888_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.EC!MTB"
        threat_id = "2147814888"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {48 8d 47 08 49 8d 54 3d 07 66 0f 1f 84 00 00 00 00 00 0f b6 08 49 89 d0 49 29 c0 48 83 c0 01 48 39 d0 4c 89 44 cc 20 75 e9}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_EC_2147814888_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.EC!MTB"
        threat_id = "2147814888"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b6 44 05 b0 83 f0 ?? 89 c2 8b 85 ?? ?? ?? ?? 48 98 88 54 05 b0 83 85 ?? ?? ?? ?? 01 81 bd ?? ?? ?? ?? ff 29 03 00 7e cf c7 85 ?? ?? ?? ?? 00 00 00 00 eb 25 8b 85 ?? ?? ?? ?? 48 98 0f b6 44 05 b0 83 f0 ?? 89 c2 8b 85 ?? ?? ?? ?? 48 98 88 54 05 b0}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_EC_2147814888_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.EC!MTB"
        threat_id = "2147814888"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {c7 44 24 50 5c 00 00 00 c7 44 24 48 65 00 00 00 c7 44 24 40 70 00 00 00 c7 44 24 38 69 00 00 00 c7 44 24 30 70 00 00 00 c7 44 24 28 5c 00 00 00 c7 44 24 20 2e}  //weight: 5, accuracy: High
        $x_2_2 = "%c%c%c%c%c%c%c%c%ckirito\\asuna" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_EC_2147814888_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.EC!MTB"
        threat_id = "2147814888"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 44 24 40 49 03 c2 42 0f b6 0c 18 b8 ?? ?? ?? ?? 44 03 c1 48 8b 8c 24 c8 00 00 00 41 f7 e8 41 03 d0 c1 fa 0e 8b c2 c1 e8 1f 03 d0 69 d2 ?? ?? ?? ?? 44 2b c2 49 63 c0 48 2b 04 24 48 03 44 24 50 48 03 44 24 60 0f b6 04 28 30 04 0b}  //weight: 1, accuracy: Low
        $x_1_2 = "m^q&5ov8aCYuRl)LdkL%D4K+NV9fS(ub)?SyIeV+%I5oYC7lyeEX#VpOmIewq!gT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_CobaltStrike_EC_2147814888_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.EC!MTB"
        threat_id = "2147814888"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {c7 44 24 50 5c 00 00 00 c7 44 24 48 65 00 00 00 c7 44 24 40 70 00 00 00 c7 44 24 38 69 00 00 00 c7 44 24 30 70 00 00 00 c7 44 24 28 5c 00 00 00 c7 44 24 20 2e}  //weight: 5, accuracy: High
        $x_2_2 = "%c%c%c%c%c%c%c%c%cwarcraft\\dota" ascii //weight: 2
        $x_2_3 = "%c%c%c%c%c%c%c%c%cralka\\ribak" ascii //weight: 2
        $x_2_4 = "%c%c%c%c%c%c%c%c%cmark\\dabollo" ascii //weight: 2
        $x_2_5 = "%c%c%c%c%c%c%c%c%cpapizor\\gojo" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_CobaltStrike_BI_2147814907_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.BI!MTB"
        threat_id = "2147814907"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 2b 04 24 48 03 44 24 ?? 48 03 44 24 ?? 0f b6 04 28 30 04 0b ff c3 48 83 ef ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_BI_2147814907_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.BI!MTB"
        threat_id = "2147814907"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 f4 48 63 d0 48 8d 85 70 ff ff ff 48 89 c1 e8 [0-4] 0f b6 00 30 45 fb 83 45 f4 01 8b 45 f4 48 63 d8 48 8d 85 70 ff ff ff 48 89 c1 e8 [0-4] 48 39 c3 0f 92 c0 84 c0 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_ABA_2147815030_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.ABA!MTB"
        threat_id = "2147815030"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 10 03 c8 b8 53 2e 97 a0 f7 e9 03 d1 c1 fa 0e 8b c2 c1 e8 1f 03 d0 48 ?? ?? ?? ?? 69 d2 06 66 00 00 2b ca 03 cd 4c 63 d1 89 8c 24 ?? ?? ?? ?? 41 0f b6 0c 02 b8 53 2e 97 a0 03 0c 24 f7 e9 03 d1 c1 fa 0e 8b c2 c1}  //weight: 1, accuracy: Low
        $x_1_2 = {49 03 c0 46 0f b6 04 18 48 8b 44 24 28 49 03 c2 42 0f b6 0c 18 b8 53 2e 97 a0 44 03 c1 41 f7 e8 41 03 d0 c1 fa 0e 8b c2 c1 e8 1f 03 d0 69 d2 06 66 00 00 44 2b c2 49 63 c0 48 03 44 24 38 48 03 44 24 48 48 03 44 24 58 48 03 44 24 68 42 8a 04 18 30 04 1f ff c7 48 83 ee 01 0f 85 0f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_CobaltStrike_PH_2147815115_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.PH!MTB"
        threat_id = "2147815115"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 33 1c 87 45 89 e0 41 c1 ec 08 45 0f b6 e4 47 0f b6 24 23 4c 8d 3d 28 48 1a 00 43 33 1c a7 45 0f b6 c0 47 0f b6 04 18 4c 8d 25 14 4c 1a 00 43 33 1c 84}  //weight: 1, accuracy: High
        $x_1_2 = {43 89 1c 81 48 ff c2 66 0f 1f 44 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_PH_2147815115_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.PH!MTB"
        threat_id = "2147815115"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 63 44 24 ?? 48 8b 4c 24 ?? 0f b6 04 01 89 44 24 ?? 48 63 4c 24 ?? 33 d2 48 8b c1 b9 15 00 00 00 48 f7 f1 48 8b c2 8b 4c 24 ?? 33 8c 84 ?? ?? ?? ?? 8b c1 48 63 4c 24 ?? 48 8b 54 24 ?? 88 04 0a eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_BK_2147815308_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.BK!MTB"
        threat_id = "2147815308"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b c3 4d 8d 40 ?? 48 f7 e1 41 ff c2 48 c1 ea ?? 48 6b c2 ?? 48 2b c8 0f b6 44 8c ?? 41 30 40 ?? 49 63 ca 48 81 f9 ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_BK_2147815308_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.BK!MTB"
        threat_id = "2147815308"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f2 0f 11 44 24 ?? 66 ?? ?? ?? ?? ?? ?? ?? ?? fe 4c 15 ?? 33 c0 0f b6 4c 15 ?? 48 ?? ?? ?? 49 ?? ?? ?? 49 ?? ?? ?? 41 ?? ?? 32 4c 04 ?? 4c 8d 48 ?? 88 8c 15 ?? ?? ?? ?? 41 ?? ?? ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_BK_2147815308_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.BK!MTB"
        threat_id = "2147815308"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c1 c9 08 e8 [0-4] 41 0f b6 0c 3c 31 c1 41 33 0e 49 ff c5 41 89 4e 20 49 83 fd 08 75 06 48 ff c7 45 31 ed 49 83 c6 04 4c 39 f5 75}  //weight: 2, accuracy: Low
        $x_2_2 = "cmd /c C:\\Windows\\Temp" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CPI_2147815519_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CPI!MTB"
        threat_id = "2147815519"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 63 44 24 24 48 8b 4c 24 28 0f b6 04 01 89 44 24 34 48 63 4c 24 24 33 d2 48 8b c1 b9 0a 00 00 00 48 f7 f1 48 8b c2 8b 4c 24 34 33 4c 84 68 8b c1 48 63 4c 24 24 48 8b 54 24 28 88 04 0a}  //weight: 1, accuracy: High
        $x_1_2 = {48 63 44 24 20 48 8b 4c 24 28 0f b6 04 01 89 44 24 30 48 63 4c 24 20 33 d2 48 8b c1 b9 ?? ?? ?? ?? 48 f7 f1 48 8b c2 8b 4c 24 30 33 4c 84 40 8b c1 48 63 4c 24 20 48 8b 54 24 28 88 04 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_CobaltStrike_PAA_2147815543_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.PAA!MTB"
        threat_id = "2147815543"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 83 ec 20 48 8b 1d [0-6] 31 ff 65 48 8b 04 25 30 00 00 00 48 8b 2d cd d0 00 00 48 8b 70 08 eb 17}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_PAA_2147815543_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.PAA!MTB"
        threat_id = "2147815543"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "okuwwgefqeg.dll" ascii //weight: 1
        $x_1_2 = "DllMainDll" ascii //weight: 1
        $x_1_3 = "RegisterServer" ascii //weight: 1
        $x_1_4 = "awowacciiuwajyn" ascii //weight: 1
        $x_1_5 = "brjvnyyakawu" ascii //weight: 1
        $x_1_6 = "cvmgghrspqaecj" ascii //weight: 1
        $x_1_7 = "dstilxaph" ascii //weight: 1
        $x_1_8 = "ieordxmvyp" ascii //weight: 1
        $x_1_9 = "kkkuiehtzdzuea" ascii //weight: 1
        $x_1_10 = "mzpydjjenaxzqhmmd" ascii //weight: 1
        $x_1_11 = "njtgkcdkfggzjsramntfufspnpfovlit" ascii //weight: 1
        $x_1_12 = "otfmvfutkcx" ascii //weight: 1
        $x_1_13 = "povmdajaysjbnn" ascii //weight: 1
        $x_1_14 = "qadpxwucgjuy" ascii //weight: 1
        $x_1_15 = "rezuiucg" ascii //weight: 1
        $x_1_16 = "wafklhepa" ascii //weight: 1
        $x_1_17 = "wzbjjmqvrdtvbnl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_BS_2147815828_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.BS!MTB"
        threat_id = "2147815828"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 45 d9 04 31 34 63 88 45 da 0f b6 45 da 04 31 34 75 88 45 db}  //weight: 1, accuracy: High
        $x_1_2 = {0f b6 54 05 d0 41 80 c0 31 0f b6 4c 05 d0 41 32 c8 44 0f b6 c2 88 4c 05 d0 48 ff c0 48 83 f8 11 72 de}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_BS_2147815828_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.BS!MTB"
        threat_id = "2147815828"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 04 24 48 8b 4c 24 20 0f be 44 01 04 48 8b 4c 24 20 0f b6 49 0b 2b c1 48 8b 4c 24 20 0f b6 49 0a 33 c1 8b 0c 24 48 8b 54 24 08 88 04 0a eb}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_BS_2147815828_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.BS!MTB"
        threat_id = "2147815828"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 c0 39 c2 7e ?? 49 89 c1 41 83 e1 ?? 47 ?? ?? ?? 44 30 0c 01 48 ff c0 eb ?? 4c 8d 05 ?? ?? ?? ?? e9}  //weight: 1, accuracy: Low
        $x_1_2 = "DllGetClassObject" ascii //weight: 1
        $x_1_3 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_BS_2147815828_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.BS!MTB"
        threat_id = "2147815828"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 44 24 ?? 0f b6 00 0f b6 4c 24 ?? 33 c1 48 8b 8c 24 ?? ?? ?? ?? 48 8b 54 24 ?? 48 2b d1 48 8b ca 0f b6 c9 81 e1 [0-4] 33 c1 48 8b 4c 24 ?? 88 01 48 63 44 24 ?? 48 8b 4c 24 ?? 48 03 c8 48 8b c1 48 89 44 24 ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_BS_2147815828_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.BS!MTB"
        threat_id = "2147815828"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 89 ee 48 c1 ee ?? 42 ?? ?? ?? ?? c1 e3 ?? c1 e1 ?? 09 d9 41 c1 e0 ?? 41 09 c8 41 09 f0 4c 8b b5 ?? ?? ?? ?? 41 0f c8 44 33 85 ?? ?? ?? ?? 48 89 c1}  //weight: 1, accuracy: Low
        $x_1_2 = {48 39 c6 74 ?? 48 39 c1 0f 84 ?? ?? ?? ?? 8a 1c 07 41 30 1c 06 48 ff c0 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_BR_2147816051_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.BR!MTB"
        threat_id = "2147816051"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4c 24 58 41 8b c3 f7 e9 d1 fa 8b c2 c1 e8 1f 03 d0 8d 04 92 3b c8 8b 44 24 58}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_BR_2147816051_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.BR!MTB"
        threat_id = "2147816051"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {48 8b 4c 24 68 39 c3 7e 16 48 89 c2 83 e2 07 41 8a 54 15 00 32 14 07 88 14 01 48 ff c0 eb}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_BR_2147816051_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.BR!MTB"
        threat_id = "2147816051"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 44 14 ?? 48 8d 52 ?? 34 ?? ff c1 88 84 15 ?? ?? ?? ?? 81 f9 ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
        $x_1_2 = {f3 0f 6f 4c 04 ?? f3 0f 7f 84 [0-10] 66 0f ef cc 66 0f ef cb 66 0f ef ca f3 0f 7f 8c ?? ?? ?? ?? ?? 81 f9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_FDS_2147816260_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.FDS!MTB"
        threat_id = "2147816260"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f be 0c 24 03 c1 0f be 0c 24 c1 e1 10 33 c1 89 44 24 04 48 8b 44 24 20 48 ff c0 48 89 44 24 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_BW_2147816267_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.BW!MTB"
        threat_id = "2147816267"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {b8 93 24 49 92 41 8b c9 41 f7 e9 41 03 d1 41 ff c1 c1 fa 02 8b c2 c1 e8 1f 03 d0 6b c2 07 2b c8 48 63 c1 0f b6 4c 84 20 42 30 4c 14 40 49 ff c2 4c 3b d7 7c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_BW_2147816267_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.BW!MTB"
        threat_id = "2147816267"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f8 66 45 ?? ?? 75 ?? 45 33 db 41 ?? ?? ?? ?? ?? 49 8b c2 0f b7 00 41 8b c9 c1 c9 ?? 41 ff c3 03 c8 41 8b c3 49 03 c2 44 33 c9 80 38 ?? 75 ?? 48 ?? ?? ?? ?? ?? ?? ?? ff c2 46}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_BW_2147816267_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.BW!MTB"
        threat_id = "2147816267"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {44 2b c2 48 8d 0c ?? 49 63 d0 44 8b ?? ?? ?? ?? ?? 48 03 d1 48 8d 04 ?? 48 2b d0 48 2b 54 ?? ?? 48 03 54 ?? ?? 49 03 d4 48 03 94 ?? ?? ?? ?? ?? 42 0f b6 04 ?? 30 04 2b ff c3 48 83 ee 01 0f 85}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_BV_2147816436_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.BV!MTB"
        threat_id = "2147816436"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 f7 e2 48 d1 ea 48 89 d0 48 01 c0 48 01 d0 48 29 c1 48 89 ca 0f b6 84 15 [0-4] 44 89 c1 31 c1 48 8b 95 [0-4] 8b 85 [0-4] 48 98 88 0c 02 83 85 [0-4] 01 8b 95 [0-4] 8b 85 [0-4] 39 c2 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_BV_2147816436_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.BV!MTB"
        threat_id = "2147816436"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 0f 4c f0 eb ?? 48 63 5c 24 ?? 48 63 7c 24 ?? 48 69 f7 ?? ?? ?? ?? 48 89 f1 48 c1 e9 ?? 48 c1 ee ?? 01 ce 6b ce ?? 29 cf 40 80 c7 ?? 40 30 7c 1c ?? 8b 5c 24 ?? ff c3 eb ?? bb ?? ?? ?? ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_BV_2147816436_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.BV!MTB"
        threat_id = "2147816436"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 e1 ff 0f 00 00 49 8b c0 48 c1 e8 [0-4] 66 29 04 11 0f b7 0f 48 8b c3 81 e1 ff 0f 00 00 48 c1 e8 [0-4] 66 01 04 11 eb [0-4] 66 83 f8 02 75 [0-4] 81 e1 ff 0f 00 00 66 44 29 04 11 0f b7 07 25 ff 0f 00 00 66 01 1c 10 48 83 c7 02 85 f6}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 32 8b 7a ?? 8b 4a ?? 49 03 ?? 49 03 ?? 41 ff ?? f3 a4 0f b7 45 ?? 48 83 c2 28 44 3b ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_HDS_2147816510_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.HDS!MTB"
        threat_id = "2147816510"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 44 24 68 83 e8 02 0f b6 c8 8b 44 24 28 d3 f8 8b 4c 24 28 83 e1 01 8d 04 41 89 44 24 2c 8b 44 24 2c 8b 4c 24 20 8d 04 c8 89 44 24 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CA_2147816757_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CA!MTB"
        threat_id = "2147816757"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 2b ce 41 ff c0 49 03 cc 02 14 39 42 32 14 [0-2] 48 8b 0d ?? ?? ?? ?? 49 63 c6 41 ff c6 88 14 [0-2] 49 63 c9 49 3b cb 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CA_2147816757_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CA!MTB"
        threat_id = "2147816757"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 44 24 47 02 c6 44 24 48 55}  //weight: 1, accuracy: High
        $x_1_2 = {80 44 24 4a 24 c6 44 24 4b 4b}  //weight: 1, accuracy: High
        $x_1_3 = {80 44 24 4f 0a c6 44 24 50 3b}  //weight: 1, accuracy: High
        $x_1_4 = {80 44 24 48 11 c6 44 24 49 4a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CA_2147816757_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CA!MTB"
        threat_id = "2147816757"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c2 c1 e8 ?? 03 d0 8b c3 ff c3 6b d2 ?? 2b c2 48 63 c8 48 8b 44 24 ?? 42 8a 8c 09 ?? ?? ?? ?? 43 32 8c 08 ?? ?? ?? ?? 41 88 0c 00 48 63 c3 49 ff c0 48 3b 44 24 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CA_2147816757_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CA!MTB"
        threat_id = "2147816757"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_8_1 = {b8 89 88 88 88 41 f7 e8 41 03 d0 c1 fa 04 8b c2 c1 e8 1f 03 d0 6b c2 0f 41 8b c9 2b c8 41 8d 04 4a 41 03 c0 48 63 c8 0f b6 14 31 41 32 14 24 43 8d 04 18 48 63 c8 88 14 19 41 ff c0 4d 8d 64 24 01 8b 4d af 03 cf 44 3b c1 72}  //weight: 8, accuracy: High
        $x_1_2 = "1v53dP2v4@fZI?SexvLU5Kz7N)t>g" ascii //weight: 1
        $x_1_3 = "CryptStringToBinaryA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CC_2147817057_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CC!MTB"
        threat_id = "2147817057"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 8b 4c 24 ?? 48 8b 49 ?? 48 c1 e9 1e 66 90 48 83 f9 04 73}  //weight: 2, accuracy: Low
        $x_3_2 = "antiSandboxChecks" ascii //weight: 3
        $x_3_3 = "executeShellcode" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CC_2147817057_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CC!MTB"
        threat_id = "2147817057"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {ff c0 48 63 f8 4c 8d 84 ?? ?? ?? ?? ?? 45 0f b6 0c ?? 41 03 d1 81 e2 ?? ?? ?? ?? 48 63 c2 48 8d 8c ?? ?? ?? ?? ?? 48 03 c8 0f b6 01 41 88 04 ?? 44 88 09 41 0f b6 04 ?? 41 03 c1 0f b6 c0 0f b6 8c ?? ?? ?? ?? ?? 41 30 0a 49 ff c2 49 83 eb 01 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CC_2147817057_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CC!MTB"
        threat_id = "2147817057"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {41 8b 0c 80 41 31 0c ?? 8b 8e ?? ?? ?? ?? 23 cb 48 8b 96 ?? ?? ?? ?? 48 63 86 ?? ?? ?? ?? 44 8b 04 82 85 c9 48 63 86 ?? ?? ?? ?? 45 03 ce 44 01 04 82 8b 86}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 0c 81 31 0a 8b 8b ?? ?? ?? ?? 81 e1 ?? ?? ?? ?? 48 8b 93 ?? ?? ?? ?? 48 63 83 ?? ?? ?? ?? 44 8b 04 82 85 c9 48 63 83 ?? ?? ?? ?? 41 ff c1 44 01 04 82 0f b6 05}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_CobaltStrike_CD_2147817299_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CD!MTB"
        threat_id = "2147817299"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 63 c9 4d 8d 52 ?? 48 8b c3 41 ff c1 48 f7 e1 48 c1 ea ?? 48 6b c2 ?? 48 2b c8 0f b6 44 8c ?? 41 30 42 ?? 41 81 f9 ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CD_2147817299_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CD!MTB"
        threat_id = "2147817299"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {41 89 c0 41 c1 f8 1f 44 29 c2 44 6b c2 ?? 44 29 c0 89 c2 89 d0 83 c0 ?? 31 c1 48 8b 95 ?? ?? 00 00 8b 85 ?? ?? 00 00 48 98 88 0c 02 83 85 ?? ?? 00 00 01 eb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_PO_2147817562_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.PO!MTB"
        threat_id = "2147817562"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 08 49 8b 4d ?? 48 63 54 24 64 48 89 94 24 ?? ?? ?? ?? 48 8b 94 24 ?? ?? ?? ?? 32 04 11 88 44 24 ?? 48 8b 84 24 ?? ?? ?? ?? 48 8b 00 48 89 84 24 ?? ?? ?? ?? b8 70 76 b2 dd e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_MP_2147818991_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MP!MTB"
        threat_id = "2147818991"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 89 c2 83 e2 07 8a 54 15 00 32 14 07 88 14 06 48 ff c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_MP_2147818991_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MP!MTB"
        threat_id = "2147818991"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ByFdiZ" ascii //weight: 1
        $x_1_2 = "VsXCzcr" ascii //weight: 1
        $x_1_3 = "VJiDT" ascii //weight: 1
        $x_1_4 = "weeulsf763bs1.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_MP_2147818991_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MP!MTB"
        threat_id = "2147818991"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4c 63 c3 49 8b c7 ff c3 49 f7 e0 48 c1 ea 04 48 8d 04 d2 48 03 c0 4c 2b c0 4d 0f af c3 42 8a 44 05 87 42 32 04 0e 41 88 01 49 ff c1 81 fb 00 ba 01 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_MP_2147818991_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MP!MTB"
        threat_id = "2147818991"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {41 f7 e8 c1 fa 03 8b c2 c1 e8 1f 03 d0 6b d2 2c 41 8b c0 2b c2 48 63 c8 42 0f b6 94 11 d8 e8 00 00 43 32 94 11 d0 53 0a 00 48 8b 44 24 30 41 88 14 01 41 ff c0 49 ff c1 49 63 c0 48 3b 44 24 38 72}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CF_2147819307_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CF!MTB"
        threat_id = "2147819307"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {65 48 8b 14 25 30 00 00 00 48 89 90 a6 08 00 00 48 8b 80 a6 08 00 00 48 8b 40 60 48 8b 40 18 48 8b 58 10 48 8d 78 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CF_2147819307_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CF!MTB"
        threat_id = "2147819307"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 63 d0 48 8b 45 ?? 48 01 d0 0f b6 08 8b 45 ?? 48 63 d0 48 8b 45 ?? 48 01 d0 44 89 c2 31 ca 88 10 83 45 ?? ?? 83 45 ?? ?? 8b 45 ?? 48 98 48 3b 45 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CF_2147819307_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CF!MTB"
        threat_id = "2147819307"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 8b 0b 48 8d 54 24 ?? 4c 8b c7 ff 15 ?? ?? ?? ?? 3d 0d 00 00 c0 74 ?? 48 83 c7 ?? 48 83 c3 ?? 48 3b dd 7c ?? 33 d2 48 8b ce ff 15 ?? ?? ?? ?? eb}  //weight: 2, accuracy: Low
        $x_1_2 = ".pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CF_2147819307_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CF!MTB"
        threat_id = "2147819307"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {41 8b 0c ae 48 01 f9 41 0f b7 44 6d ?? 41 8b 34 84 e8 ?? ?? ?? ?? 48 01 fe 39 44 24 ?? 48 0f 44 de 48 ff c5 eb}  //weight: 2, accuracy: Low
        $x_2_2 = {0f be 11 85 d2 74 ?? 31 d0 69 d0 ?? ?? ?? ?? 89 d0 c1 e8 ?? 31 d0 48 ff c1 eb}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CF_2147819307_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CF!MTB"
        threat_id = "2147819307"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {74 63 65 74 48 8b d3 c7 ?? 24 44 6f 72 50 6c 41 b8 [0-4] c7 44 24 ?? 61 75 74 72 66 c7 44 24 ?? 69 56 0f b6 44 14 ?? 42 0f b6 4c 04 ?? 42 88 44 04 ?? 49 ff c8 88 4c 14 ?? 48 ff c2 49}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CG_2147819308_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CG!MTB"
        threat_id = "2147819308"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0f b6 c3 40 2a c7 24 10 32 03 40 32 c6 88 03 48 03 d9 49 3b dd 72 ?? 8b 44 24 ?? 49 ff c4 49 ff c6 49 ff cf 0f 85}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CG_2147819308_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CG!MTB"
        threat_id = "2147819308"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 8d 8d 80 00 00 00 e8 ?? ?? 00 00 48 8d 15 ?? ?? 01 00 48 8d 4d 00 e8 ?? ?? 00 00 48 8d 15 ?? ?? 01 00 48 8d 8d 80 00 00 00 e8 ?? ?? 00 00 48 8d 15 ?? ?? 01 00 48 8d 4d 00 e8 ?? ?? 00 00 48 8d 15 ?? ?? 01 00 48 8d 8d 80 00 00 00 e8}  //weight: 5, accuracy: Low
        $x_5_2 = {83 e8 03 48 98 c6 84 05 ?? ?? 00 00 00 48 8d 15 ?? ?? 01 00 48 8d 8d ?? ?? 00 00 e8}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CG_2147819308_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CG!MTB"
        threat_id = "2147819308"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 c0 48 c1 e0 ?? 48 01 45 ?? 81 7d ?? ?? ?? ?? ?? 75 ?? 48 8b 45 ?? 8b 00 89 c2 48 8b 45 ?? 48 01 d0 48 ?? ?? ?? 0f b7 45 ?? 83 e8 ?? 66 89 45 ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 66 ?? ?? ?? ?? 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 c1 48 8b 45 ?? 48 8d 50 ?? 48 89 55 ?? 48 89 c2 0f b6 01 88 02 48 8b 45 ?? 48 8d 50 ?? 48 89 55 ?? 48 85 c0 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_EE_2147819532_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.EE!MTB"
        threat_id = "2147819532"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "//rs.qbox.me/chtype/" ascii //weight: 1
        $x_1_2 = "Dbak/chdb:qiniu.png" ascii //weight: 1
        $x_1_3 = "RGJhay9jaGRiOnFpbml1LnBuZw==" ascii //weight: 1
        $x_1_4 = "AcquireCredentialsHandle" ascii //weight: 1
        $x_1_5 = "base64 encoding" ascii //weight: 1
        $x_1_6 = "Kerberos" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_SHL_2147819995_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.SHL!MTB"
        threat_id = "2147819995"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 88 0c 1c 48 ff c3 41 f7 e9 41 03 d1 c1 fa 07 8b c2 c1 e8 1f 03 d0 41 8b c1 41 ff c1 69 d2 d9 00 00 00 2b c2 48 98 0f b6 0c 38 88 8c 1c ff 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_SHM_2147819996_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.SHM!MTB"
        threat_id = "2147819996"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 5c 04 21 89 da f6 d2 80 e2 15 80 e3 ea 08 d3 88 5c 04 21}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_C_2147828445_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.C!MTB"
        threat_id = "2147828445"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 b9 40 00 00 00 41 b8 00 30 00 00 b9 00 00 00 00 ff d0 49 89 ?? 48 8d 15 ?? ?? ?? ?? b9 06 00 00 00 b8 00 00 00 00 48 89 d7 f3 48 ab}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_C_2147828445_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.C!MTB"
        threat_id = "2147828445"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {48 8d 55 fc 48 8d 05 8d 1b 00 00 49 89 d1 41 b8 40 00 00 00 ba 4e 88 05 00 48 89 c1 48 8b 05 ?? ?? ?? ?? ff d0}  //weight: 3, accuracy: Low
        $x_2_2 = {48 83 ec 30 48 89 4d 10 48 8b 45 10 48 89 45 f8 48 8b 45 f8 ff d0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_E_2147828566_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.E!MTB"
        threat_id = "2147828566"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 63 84 24 a0 06 00 00 0f b6 bc 04 10 01 00 00 8b 84 24 a0 06 00 00 99 b9 ?? 00 00 00 f7 f9 48 63 ca 48 8b 05 ea 08 01 00 0f b6 04 08 8b d7 33 d0 48 63 8c 24 a0 06 00 00 48 8b 05 fb 08 01 00 88 14 08 eb 9d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_BM_2147828678_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.BM!MTB"
        threat_id = "2147828678"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {41 ff c0 49 63 c8 48 8d 54 24 30 48 03 d1 0f b6 0a 41 88 09 44 88 12 41 0f b6 09 41 03 ca 0f b6 d1 0f b6 4c 14 30 32 0c 1e 88 0b 48 ff c3 48 83 ed 01 75}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_BM_2147828678_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.BM!MTB"
        threat_id = "2147828678"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {42 0f b6 0c 2b 09 c1 0f c9 41 33 08 0f c9 43 89 4c 32 0c 31 c0 48 8b 94 24 80 00 00 00 48 8b 6c 24 70 48 83 f8 10 74 ?? 8a 0c 02 30 4c 05 00 48 ff c0 eb}  //weight: 1, accuracy: Low
        $x_1_2 = "4Bejz8txQ/rDnf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_BM_2147828678_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.BM!MTB"
        threat_id = "2147828678"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 63 d0 48 ?? ?? ?? ?? ?? ?? 48 01 d0 44 0f b6 00 8b 85 ?? ?? ?? ?? 48 63 d0 48 ?? ?? ?? ?? ?? ?? 48 c1 ea ?? 01 c2 c1 fa ?? 89 c1 c1 f9 ?? 29 ca 6b ca ?? 29 c8 89 c2 89 d0 83 c0 ?? 44 89 c1 31 c1 48 ?? ?? ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 48 98 88 0c 02 83 85 ?? ?? ?? ?? ?? 83 bd}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_DK_2147828780_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.DK!MTB"
        threat_id = "2147828780"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 28 4c 08 d0 0f 57 c8 0f 28 54 08 e0 0f 57 d0 0f 29 4c 08 d0 0f 29 54 08 e0 0f 28 4c 08 f0 0f 57 c8 0f 28 14 08 0f 57 d0 0f 29 4c 08 f0 0f 29 14 08 48 83 c0 ?? 48 3d [0-5] 75}  //weight: 1, accuracy: Low
        $x_1_2 = "ShellCodeLoader\\bin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_DK_2147828780_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.DK!MTB"
        threat_id = "2147828780"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 c9 48 8d 15 ?? ?? 00 00 33 04 8a b9 04 00 00 00 48 6b c9 07 48 8b 54 24 20 33 04 0a 89 44 24 1c 48 8b 44 24 20 48 83 c0 20 48 89 44 24 20 8b 44 24 2c ff c8 89 44 24 2c 83 7c 24 2c 00 75}  //weight: 2, accuracy: Low
        $x_2_2 = {49 8d 04 12 41 83 c0 04 41 8b 4c 01 f8 8b 40 f8 33 0a 89 02 48 8d 52 04 41 89 4c 13 f4 44 3b 43 04 7c}  //weight: 2, accuracy: High
        $x_1_3 = "ReflectiveLoader" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_MKV_2147828925_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MKV!MTB"
        threat_id = "2147828925"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 33 c0 c7 44 24 20 ?? ?? ?? ?? 48 8d 55 ?? 48 8d 4b ?? e8 ?? ?? ?? ?? 8b d3 4c 8d 45 ?? 41 0f b6 ?? 4d 8d 40 ?? 48 63 c2 80 f1 69 48 03 45 ?? ff c2 88 08 81 fa ?? ?? ?? ?? 76}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_ST_2147829004_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.ST!MTB"
        threat_id = "2147829004"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 45 b8 48 8b 55 e0 4c 8b 45 b0 8a 4d af 42 32 0c 02 88 08 48 8b 45 08 48 83 c0 01 48 89 45 a0 0f 92 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_ST_2147829004_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.ST!MTB"
        threat_id = "2147829004"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SCvoNuWGbfHRc" ascii //weight: 1
        $x_1_2 = "ZExCXMamiESzKzkNC" ascii //weight: 1
        $x_1_3 = "eLhVPDbYLFjKOM" ascii //weight: 1
        $x_1_4 = "pMHdJLDjJmVYaqbPC" ascii //weight: 1
        $x_1_5 = "uurWrUBNxKuNVa" ascii //weight: 1
        $x_1_6 = "OIdxgIWUEHM" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_MKVB_2147829039_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MKVB!MTB"
        threat_id = "2147829039"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f0 41 c0 e6 ?? 8b c8 c1 e9 ?? 41 32 ce 80 e1 ?? 41 32 ce 48 8b 55 ?? 4c 8b 45 ?? 49 3b d0 73 ?? 48 8d 42 ?? 48 89 45 ?? 48 8d 45 ?? 49 83 f8 ?? 48 0f 43 45 ?? 88 0c 10 c6 44 10 01 ?? eb ?? 44 0f b6 c9 48 8d 4d ?? e8 ?? ?? ?? ?? 4d 3b fc 0f 83}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_MKVD_2147829351_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MKVD!MTB"
        threat_id = "2147829351"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 83 f8 0d 49 63 c8 48 8b d3 4d 8d 49 ?? 48 0f 45 d0 48 03 4d ?? 41 ff c0 0f b6 44 14 ?? 41 32 41 ?? 88 01 48 8d 42 ?? 41 81 f8 ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_SL_2147829381_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.SL!MTB"
        threat_id = "2147829381"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 7c 24 7c ?? 0f ae e8 7d ?? 48 8b 84 24 ?? ?? ?? ?? 0f ae e8 48 63 54 24 7c 0f ae e8 0f be 0c 10 8b 44 24 ?? 41 b9 ?? ?? ?? ?? 99 41 f7 f9 83 c2 ?? 31 d1 48 63 44 24 ?? 0f ae e8 41 88 0c 00 8b 44 24 ?? 83 c0 ?? 89 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_MKVG_2147829946_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MKVG!MTB"
        threat_id = "2147829946"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c8 99 f7 fb 0f b6 04 17 30 04 0e 8d 41 ?? 99 f7 fb 0f b6 04 17 30 44 0e ?? 48 83 c1 ?? 48 39 cd 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_RUS_2147829961_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.RUS!MTB"
        threat_id = "2147829961"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8d 6c 24 40 48 89 4d e8 48 89 55 f0 66 c7 45 f8 01 00 48 8d 4d e8 e8 5f 2e 04 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_RUS_2147829961_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.RUS!MTB"
        threat_id = "2147829961"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 c1 e0 3a 49 c1 e2 34 4d 09 c2 49 c1 e3 2e 4d 09 d3 49 c1 e7 28 4d 09 df 48 c1 e2 22 4c 09 fa 48 c1 e5 1c 48 09 d5 48 c1 e1 16 48 09 e9 48 c1 e6 10 48 09 ce ba 08 00 00 00 31 c9 49 89 c0 e8 ?? ?? ?? ?? 48 0f ce 48 89 74 24}  //weight: 1, accuracy: Low
        $x_1_2 = "360sdtray" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_MKI_2147830084_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MKI!MTB"
        threat_id = "2147830084"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 c2 41 f6 f7 48 83 fa ?? 74 ?? 0f b6 c0 6b c0 ?? 89 d9 28 c1 30 8c 15 ?? ?? ?? ?? 48 ff c2 fe c3 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_BMM_2147830133_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.BMM!MTB"
        threat_id = "2147830133"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e0 18 41 89 00 41 0f b6 51 fd c1 e2 10 0b d0 41 89 10 41 ?? ?? ?? ?? c1 e1 08 0b ca 49 8b d0 41 89 08 41 ?? ?? ?? ?? 0b c1 41 89 00 49 83 c0 04 41 33 02 4d 8d 52 04 89 02 49 83 ec 01 75}  //weight: 1, accuracy: Low
        $x_1_2 = {5c 78 39 31 5c 78 65 31 5c 78 61 31 39 [0-7] 5c 78 45 39 5c 78 45 38 5c 58 61 31 [0-6] [0-9] 72 30 78 31 30 78 31 30 78 31 [0-17] 4b 4b 42 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_BMN_2147830134_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.BMN!MTB"
        threat_id = "2147830134"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 4c 24 08 48 89 54 24 10 4c 89 44 24 18 4c 89 4c 24 20 48 83 ec 28 b9 ?? ?? ?? ?? e8 ?? ?? ff ff 4c 8b f8 b9 ?? ?? ?? ?? e8 ?? ?? ff ff 48 83 c4 28 48 8b 4c 24 08 48 8b 54 24 10 4c 8b 44 24 18 4c 8b 4c 24 20 4c 8b d1 41 ff e7}  //weight: 1, accuracy: Low
        $x_1_2 = {89 05 8b 38 02 00 c7 44 24 28 40 00 00 00 c7 44 24 20 00 30 00 00 4c 8d [0-7] 45 33 c0 48 8d 15 15 39 02 00 48 c7 c1 ff ff ff ff e8}  //weight: 1, accuracy: Low
        $x_1_3 = {25 42 eb 96 f3 89 05 a8 3f 02 00 8b 05 a6 3f 02 00 05 7a 9f cc f4 89 05 97 3f 02 00 8b 05 91 3f 02 00 35 88 e8 83 a3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_BNN_2147830135_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.BNN!MTB"
        threat_id = "2147830135"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {35 78 81 b2 db 89 05 45 df 03 00 0f b7 05 3a df 03 00 48 b9 [0-9] 48 03 c1 48 89 05 36 df 03 00 8b 04 24 89 44 24 10 e9 65 f9 ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {35 3d dc 00 00 66 89 05 a9 de 03 00 0f b6 05 9a de 03 00 35 8a 00 00 00 88 05 8f de 03 00 0f b7 05 8c de 03 00 25 be 35 00 00 66 89 05 84 de 03 00 0f b7 05 7d de 03 00 25 e7 5a 53 a1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_SP_2147830497_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.SP!MTB"
        threat_id = "2147830497"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 8b d0 c1 ea 08 88 14 01 [0-112] 41 03 c2 09 43 ?? 89 8b ?? 00 00 00 8d 81 ?? ?? ?? ?? 09 43 ?? 49 81 f9 ?? ?? ?? 00 0f 8c ?? ff ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_SP_2147830497_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.SP!MTB"
        threat_id = "2147830497"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 01 d9 66 ?? ?? ?? ?? 75 ?? e8 ?? ?? ?? ?? 41 ?? ?? ff c6 49 ?? ?? ?? 4d ?? ?? 41}  //weight: 1, accuracy: Low
        $x_1_2 = {39 c3 7e 1b 48 ?? ?? 48 ?? ?? ?? ?? 83 e2 ?? 41 ?? ?? ?? ?? 32 14 07 88 14 01 48 ?? ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_SP_2147830497_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.SP!MTB"
        threat_id = "2147830497"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "0ZNA3EZ4g.exe" ascii //weight: 1
        $x_1_2 = "0ZNA3EZ4g.xlsx" ascii //weight: 1
        $x_1_3 = "50dlxJe" ascii //weight: 1
        $x_1_4 = "winrarsfxmappingfile.tmp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_SP_2147830497_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.SP!MTB"
        threat_id = "2147830497"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {33 d2 46 88 44 0c 40 41 8b c0 4d 8d 49 01 f7 f7 41 ff c0 0f b6 44 14 30 42 88 84 0c 3f 01 00 00 41 81 f8 00 01 00 00 7c d7}  //weight: 4, accuracy: High
        $x_2_2 = {0f b6 84 14 40 01 00 00 44 0f b6 44 14 40 03 d8 41 03 d8 81 e3 ff 00 00 80 7d 0a ff cb 81 cb 00 ff ff ff ff c3 48 63 c3 48 8d 4c 24 40 48 03 c8 0f b6 01 88 44 14 40 48 ff c2 44 88 01 49 83 e9 01 75 bd}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_KJ_2147830523_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.KJ!MTB"
        threat_id = "2147830523"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 44 24 20 04 00 00 00 41 b9 00 10 00 00 41 b8 90 00 00 00 48 8b ce ff 15}  //weight: 1, accuracy: High
        $x_1_2 = "legacy.chunk.js" ascii //weight: 1
        $x_1_3 = {77 69 6e 64 6f 77 73 5c 74 65 6d 70 5c [0-2] 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_KJ_2147830523_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.KJ!MTB"
        threat_id = "2147830523"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff c0 89 85 ?? ?? ?? ?? 8b 45 ?? 39 85 ?? ?? ?? ?? 7d ?? 8b 85 ?? ?? ?? ?? 83 c0 ?? 99 f7 7d ?? 8b c2 89 85}  //weight: 1, accuracy: Low
        $x_1_2 = {0f be 0c 0a 33 c1 48 63 8d ?? ?? ?? ?? 48 8b 95 ?? ?? ?? ?? 88 04 0a eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_SM_2147830777_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.SM!MTB"
        threat_id = "2147830777"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c1 48 63 8a ?? ?? ?? ?? 89 82 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 45 ?? ?? ?? 49 ?? ?? ?? 44 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 45 ?? ?? 41 ?? ?? ?? 44 ?? ?? ?? ff 82 ?? ?? ?? ?? 44 ?? ?? ?? ?? ?? ?? 41 ?? ?? 33 8a ?? ?? ?? ?? 8b 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_LK_2147830796_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.LK!MTB"
        threat_id = "2147830796"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {49 ba 70 2a 57 34 48 1f bc d6 48 8b 4c 24 60 48 8b d6 48 89 4c 24 20 4c 8b c7 48 8b cd 44 8b cb ff 15}  //weight: 5, accuracy: High
        $x_1_2 = "tasks\\CredDump.rar" wide //weight: 1
        $x_1_3 = "FUCK" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_LO_2147830797_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.LO!MTB"
        threat_id = "2147830797"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 b9 40 00 00 00 48 63 d8 41 b8 00 30 00 00 48 8b d3 33 c9 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {b9 88 13 00 00 48 8b f8 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {ff c8 33 d2 89 41 38 41 8b c3 f7 f3 80 c2 30 44 8b d8 80 fa 39 7e 0c 41 8a c1 34 01 c0 e0 05 04 07 02 d0 48 8b 41 48 88 10 48 ff 49 48 eb c5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_NS_2147830891_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.NS!MTB"
        threat_id = "2147830891"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {41 b9 40 00 00 00 41 b8 00 10 00 00 8b ?? 33 ?? ff 15}  //weight: 2, accuracy: Low
        $x_1_2 = "UtilExportFunctions" ascii //weight: 1
        $x_2_3 = {c5 fd 7f 09 c5 fd 7f 51 ?? c5 fd 7f 59 ?? c5 fd 7f 61 ?? c5 fe 6f 8a ?? ?? ?? ?? c5 fe 6f 92 ?? ?? ?? ?? c5 fe 6f 9a ?? ?? ?? ?? c5 fe 6f a2 ?? ?? ?? ?? c5 fd 7f 89 ?? ?? ?? ?? c5 fd 7f 91 ?? ?? ?? ?? c5 fd 7f 99 ?? ?? ?? ?? c5 fd 7f a1 ?? ?? ?? ?? 48 81 c1 00 01 00 00 48 81 c2 00 01 00 00 49 81 e8 00 01 00 00 49 81 f8 00 01 00 00 0f 83 78 ff ff ff}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_VA_2147831499_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.VA!MTB"
        threat_id = "2147831499"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 b9 40 00 00 00 41 b8 00 30 00 00 48 8b 15 53 00 00 00 48 31 c9 e8}  //weight: 1, accuracy: High
        $x_1_2 = {48 8d 8d e0 04 00 00 48 8b 95 d8 04 00 00 4c 8b c8 48 89 4c 24 30 4c 8b c3 48 8d 8d e8 04 00 00 48 89 4c 24 28 48 8d 4d f0 48 89 4c 24 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_HC_2147831566_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.HC!MTB"
        threat_id = "2147831566"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8d 0d ab 70 3e 00 48 89 88 90 00 00 00 48 8d 0d 9e 70 3e 00 48 89 88 b0 00 00 00 48 8d 0d 91 70 3e 00 48 89 88 d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_FYY_2147831873_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.FYY!MTB"
        threat_id = "2147831873"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 89 44 24 58 45 33 c0 33 d2 b9 00 00 04 00 ff 15 6b 20 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {48 8b 4c 24 30 45 33 c9 ba 01 68 00 00 48 89 44 24 20 ff 15 33 1f 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {44 8b 05 f9 7e 01 00 48 8b d3 48 8b 0d 8f 88 01 00 e8 91 0e 00 00 48 8b 15 83 88 01 00 45 33 c0 33 c9 ff 15 90 1f 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_SD_2147832095_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.SD!MTB"
        threat_id = "2147832095"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 63 c8 48 8d 94 24 ?? ?? ?? ?? 48 03 d1 0f b6 0a 41 88 0c 30 44 88 0a 41 0f b6 14 30 49 03 d1 0f b6 ca 0f b6 94 0c ?? ?? ?? ?? 41 30 12 49 ff c2 49 83 eb 01 75 91}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_SD_2147832095_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.SD!MTB"
        threat_id = "2147832095"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 00 48 ?? ?? ?? ?? ?? ?? ?? 0f b6 09 33 c1 88 44 24 ?? 48 ?? ?? ?? ?? 48 45 00 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? 48 ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_JAS_2147832134_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.JAS!MTB"
        threat_id = "2147832134"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 b9 40 00 00 00 41 b8 00 30 00 00 8b d6 33 c9 ff d0}  //weight: 1, accuracy: High
        $x_1_2 = {b8 3f c5 25 43 41 f7 ea c1 fa 04 8b c2 c1 e8 1f 03 d0 6b c2 3d 41 8b d2 41 ff c2 2b d0 48 8b 05 67 ae 09 00 4c 63 c2 45 8a 04 00 47 32 04 0e 45 88 01 49 ff c1 48 83 ee 01 75 c5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_SMW_2147832330_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.SMW!MTB"
        threat_id = "2147832330"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {f3 0f 6f 0a f3 0f 6f 52 10 f3 0f 6f 5a 20 f3 0f 6f 62 30 66 0f 7f 09 66 0f 7f 51 10 66 0f 7f 59 20 66 0f 7f 61 30 f3 0f 6f 4a 40 f3 0f 6f 52 50 f3 0f 6f 5a 60 f3 0f 6f 62 70 66 0f 7f 49 40 66 0f 7f 51 50 66 0f 7f 59 60 66 0f 7f 61 70 48 81 c1 80 00 00 00 48 81 c2 80 00 00 00 49 81 e8 80 00 00 00 49 81 f8 80 00 00 00 73 94}  //weight: 10, accuracy: High
        $x_10_2 = {45 33 c9 44 8b c0 48 8b 94 24 c0 00 00 00 48 8b 4c 24 48 ff 54 24 68 85 c0 75 07}  //weight: 10, accuracy: High
        $x_1_3 = "Passw0rd!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_SMW_2147832330_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.SMW!MTB"
        threat_id = "2147832330"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[i] Injecting The Reflective DLL Into" ascii //weight: 1
        $x_1_2 = "[!] CreateToolhelp32Snapshot Failed With Error :" ascii //weight: 1
        $x_1_3 = "RlfDllInjector.pdb" ascii //weight: 1
        $x_1_4 = "[!] CreateRemoteThread Failed With Error: " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_RD_2147832385_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.RD!MTB"
        threat_id = "2147832385"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b e8 44 8b f3 41 b9 40 00 00 00 41 b8 00 10 00 00 8b d3 33 c9 ff 15 0a ee}  //weight: 1, accuracy: High
        $x_1_2 = {0f 57 c0 48 8d 53 08 48 89 0b 48 8d 48 08 0f 11 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_RD_2147832385_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.RD!MTB"
        threat_id = "2147832385"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 89 4c 24 50 48 8d 44 24 70 48 89 4c 24 48 41 b9 ff 01 0f 00 48 89 4c 24 40 48 8b cb 48 89 44 24 38 c7 44 24 30 01 00 00 00 c7 44 24 28 03 00 00 00 c7 44 24 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_WM_2147832607_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.WM!MTB"
        threat_id = "2147832607"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 47 50 41 8b d2 69 88 ?? ?? ?? ?? ?? ?? ?? ?? 48 8b 47 ?? 44 03 c1 41 8b c8 d3 ea 8a 48 ?? 48 8b 47 ?? 80 f1 d0 22 d1 48 63 8f ?? ?? ?? ?? 88 14 01 01 b7 ?? ?? ?? ?? 48 8b 47 ?? 48 39 07 76 ?? 48 8b 47 ?? 48 8b 88 ?? ?? ?? ?? 48 81 c1 ?? ?? ?? ?? 48 31 4f ?? 48 8b 87 ?? ?? ?? ?? 48 05 ?? ?? ?? ?? 48 09 87 ?? ?? ?? ?? 45 85 c0 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_WR_2147832730_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.WR!MTB"
        threat_id = "2147832730"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 89 c1 31 c0 39 c3 7e ?? 48 89 c2 83 e2 03 8a 14 17 32 14 06 41 88 14 01 48 ff c0 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_HW_2147832881_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.HW!MTB"
        threat_id = "2147832881"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c2 24 01 f6 d8 1a c9 ff c2 80 e1 f1 48 63 c2 80 c1 ea 41 30 08 49 ff c0 49 3b c1 72 e2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_WN_2147832977_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.WN!MTB"
        threat_id = "2147832977"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 d2 4d 8d 5b 01 48 f7 f5 ff c7 42 0f b6 04 32 42 32 44 1e ff 41 88 43 ff 48 63 c7 48 3b c3 72 df}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_PCA_2147833042_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.PCA!MTB"
        threat_id = "2147833042"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 44 24 30 48 8d 15 ?? ?? ?? ?? 48 8b 4c 24 30}  //weight: 1, accuracy: Low
        $x_1_2 = {41 b9 40 00 00 00 41 b8 00 30 00 00 48 8b 54 24 28 33 c9 ff 54 24 38 48 8b 8c 24 80 00 00 00 48 89 41 18}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_PCB_2147833043_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.PCB!MTB"
        threat_id = "2147833043"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 44 15 fb 8b 4d f7 32 c8 88 4c 15 fb 48 ff c2 48 83 fa 3c 72 e9}  //weight: 1, accuracy: High
        $x_1_2 = {41 0f b6 42 02 0f b6 0c 38 41 0f b6 42 03 49 83 c2 04 c0 e1 06 0a 0c 38 41 88 49 02 49 83 c1 03 48 83 eb 01}  //weight: 1, accuracy: High
        $x_1_3 = "windows.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_SB_2147833417_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.SB!MTB"
        threat_id = "2147833417"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 09 49 30 44 33 81 ?? ?? ?? ?? 41 2b c0 01 41 ?? 48 8b 81 ?? ?? ?? ?? 0f b6 51 ?? 45 0f b6 04 03 49 83 c3 ?? 48 8b 81 ?? ?? ?? ?? 44 0f af c2 48 63 51}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_SB_2147833417_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.SB!MTB"
        threat_id = "2147833417"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b c1 c7 44 24 40 3a 51 7c ab 83 e0 0f c7 44 24 44 0e 15 70 0f c7 44 24 48 22 19 a4 b3 c7 44 24 4c 76 5d 18 97 0f 28 44 24 40 66 0f 7f 44 24 60 0f b6 44 04 60 32 84 11 b8 99 01 00 88 44 0c 50 48 ff c1 48 83 f9 0c 72 b6}  //weight: 1, accuracy: High
        $x_1_2 = "DllCanUnloadNow" ascii //weight: 1
        $x_1_3 = "DllGetClassObject" ascii //weight: 1
        $x_1_4 = "runWorker" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_WA_2147833419_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.WA!MTB"
        threat_id = "2147833419"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b cb f7 eb 03 d3 ff c3 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 6b c2 ?? 2b c8 48 63 c1 42 8a 0c 00 43 32 0c 0a 41 88 09 49 ff c1 49 83 ef ?? 74 ?? 4c 8b 05 ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_PSS_2147833442_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.PSS!MTB"
        threat_id = "2147833442"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c9 44 8b c3 48 8b d7 ff 15 9a 49 04 00}  //weight: 1, accuracy: High
        $x_1_2 = {41 f7 e9 c1 fa 04 8b c2 c1 e8 ?? 03 d0 41 8b c1 41 ff c1 6b d2 42 2b c2 48 63 c8 48 8d 05 10 93 04 00 8a 04 01 43 32 04 10 41 88 02 49 ff c2 44 3b cf 72 c7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_PCE_2147833579_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.PCE!MTB"
        threat_id = "2147833579"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 83 68 01 00 00 41 b9 33 36 00 00 48 8b 8b 80 01 00 00 45 8b 1c 00 49 8b 06 48 33 c5 48 01 41 58 8b 83 40 01 00 00 44 0f af 9b 30 01 00 00 05 4c 03 00 00 44 8b 93 64 01 00 00 41 3b c1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_BN_2147833637_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.BN!MTB"
        threat_id = "2147833637"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 44 1d 3b 8b 4d 37 02 cb 32 c8 88 4c 1d 3b 48 ff c3 48 83 fb 0b 72 e7}  //weight: 1, accuracy: High
        $x_1_2 = "windows.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_BN_2147833637_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.BN!MTB"
        threat_id = "2147833637"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 8b 55 c0 8b 85 [0-4] 48 98 48 01 d0 44 0f b6 00 8b 85 [0-4] 48 98 0f b6 4c 05 ca 48 8b 55 c0 8b 85 [0-4] 48 98 48 01 d0 44 89 c2 31 ca 88 10 83 85 [0-4] 01 83 85 [0-4] 01 eb}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_BN_2147833637_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.BN!MTB"
        threat_id = "2147833637"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 fc 3b 45 ?? 7d ?? 8b 45 ?? 48 63 d0 48 ?? ?? ?? 48 01 d0 44 0f b6 00 0f b6 4d ?? 8b 45 ?? 48 63 d0 48 ?? ?? ?? 48 01 d0 44 89 c2 31 ca 88 10 83 45 ?? ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_VTK_2147833753_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.VTK!MTB"
        threat_id = "2147833753"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "\\Parallel_Asis.dll" ascii //weight: 5
        $x_5_2 = "Rfc2898DeriveBytes" ascii //weight: 5
        $x_5_3 = "41B649903F29EBDD1C1C8A68F8CE6513C7BBBBB11553564A537C26CAA1C7BD1A" ascii //weight: 5
        $x_5_4 = "sc_output" wide //weight: 5
        $x_5_5 = "(FunctionPointer) [+] NtProtectVirtualMemory, PAGE_EXECUTE_READ" wide //weight: 5
        $x_1_6 = "baseball" wide //weight: 1
        $x_1_7 = "baseb@ll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_CobaltStrike_PCF_2147833804_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.PCF!MTB"
        threat_id = "2147833804"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {f3 0f 6f 4a 40 f3 0f 6f 52 50 f3 0f 6f 5a 60 f3 0f 6f 62 70 66 0f 7f 49 40 66 0f 7f 51 50 66 0f 7f 59 60 66 0f 7f 61 70 48 81 c1 80 00 00 00 48 81 c2 80 00 00 00 49 81 e8 80 00 00 00 49 81 f8 80 00 00 00 73 94 4d 8d 48 0f 49 83 e1 f0 4d 8b d9 49 c1 eb 04 47 8b 9c 9a 28 45 00 00 4d 03 da 41 ff e3}  //weight: 4, accuracy: High
        $x_4_2 = {48 8d 44 24 48 48 89 44 24 20 45 33 c9 45 33 c0 ba 0c 80 00 00 48 8b 4c 24 40 ff 54 24 60}  //weight: 4, accuracy: High
        $x_2_3 = "Sup3rS3cur3P4ss!1" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_NAH_2147833963_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.NAH!MTB"
        threat_id = "2147833963"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 44 24 38 48 8b 54 24 ?? c1 e0 04 48 c1 fa 02 09 d0 43 88 44 25 ?? 49 83 c4 01 71 ?? ?? ?? ?? ?? ?? 49 8b 55}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 84 24 98 00 00 00 42 8a 54 25 ?? 32 94 1e ?? ?? ?? ?? 42 88 14 20 4c 89 e0 48 83 c0 01 49 89 c4 71 ?? ?? ?? ?? ?? ?? 48 ff c3 83 e3 0f e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_BAN_2147834006_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.BAN!MTB"
        threat_id = "2147834006"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 57 48 81 ec 38 01 00 00 48 8d ac 24 80 00 00 00 48 c7 45 a0 00 00 00 00 48 c7 45 a8 00 00 00 00 48 8d 55 b0 b8 00 00 00 00 b9 1e 00 00 00 48 89 d7 f3 48 ab 48 89 fa 89 02 48 83 c2 04 c7 85 ac 00 00 00 00 00 00 00 48 8d 45 a0 41 b8 04 01 00 00 48 89 c2 b9 00 00 00 00 48 8b 05 ?? ?? ?? ?? ff d0 89 85 ac 00 00 00 83 bd ac 00 00 00 00 75 07 b8 00 00 00 00 eb 2d 48 8d 45 a0 48 8d 15 ?? ?? ?? ?? 48 89 c1 e8 ?? ?? ?? ?? 48 85 c0 75 07 b8 00 00 00 00 eb 0e 48 8d 05 ?? ?? ?? ?? ff d0 b8 01 00 00 00 48 81 c4 38 01 00 00 5f 5d c3}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 00 00 00 00 00 e9 9e fe ff ff 66 66 2e 0f 1f 84 00 00 00 00 00 0f 1f 00 48 89 ca 48 8d 0d [0-11] 48 8d 0d 09 00 00 00 e9 e4 ff ff ff 0f 1f 40 00 c3}  //weight: 1, accuracy: Low
        $x_1_3 = "CorGetSvc" ascii //weight: 1
        $x_1_4 = "mscorsvc.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_NV_2147834093_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.NV!MTB"
        threat_id = "2147834093"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {c5 fe 6f 0a c5 fe 6f 52 20 c5 fe 6f 5a 40 c5 fe 6f 62 60 c5 fd 7f 09 c5 fd 7f 51 20 c5 fd 7f 59 40 c5 fd 7f 61 60 c5 fe 6f 8a 80 00 00 00 c5 fe 6f 92 a0 00 00 00 c5 fe 6f 9a c0 00 00 00 c5 fe 6f a2 e0 00 00 00 c5 fd 7f 89 80 00 00 00 c5 fd 7f 91 a0 00 00 00 c5 fd 7f 99 c0 00 00 00 c5 fd 7f a1 e0 00 00 00 48 81 c1 00 01 00 00 48 81 c2 00 01 00 00 49 81 e8 00 01 00 00 49 81 f8 00 01 00 00 0f 83 78 ff ff ff}  //weight: 5, accuracy: High
        $x_5_2 = {c4 a1 7e 6f 4c 0a c0 c4 a1 7e 7f 4c 09 c0 c4 a1 7e 7f 6c 01 e0 c5 fe 7f 00 c5 f8 77 c3}  //weight: 5, accuracy: High
        $x_1_3 = {c7 44 24 48 00 40 00 00 c7 44 24 4c 00 00 00 00 48 8b 44 24 58 48 89 44 24 50 48 8d 4c 24 38 e8}  //weight: 1, accuracy: High
        $x_1_4 = "Z:\\libs\\ZBar\\zbar\\refcnt.h" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_CobaltStrike_LP_2147834193_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.LP!MTB"
        threat_id = "2147834193"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e8 00 00 00 00 48 33 c9 65 48 8b 41 60 48 8b 40 18 48 8b 70 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_LP_2147834193_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.LP!MTB"
        threat_id = "2147834193"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 8b c0 99 83 e2 ?? 03 c2 83 e0 ?? 2b c2 48 63 c8 42 0f b6 04 19 43 32 04 0a 41 88 01 41 ff c0 49 ff c1 41 81 f8 ?? ?? ?? ?? 72 d4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_MST_2147834285_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MST!MTB"
        threat_id = "2147834285"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 8b 84 24 f8 00 00 00 8b 0c 03 41 33 8c 24 ?? ?? ?? ?? 49 8b 84 24 ?? ?? ?? ?? 89 0c 03 49 81 bc 24 ?? ?? ?? ?? ?? ?? ?? ?? 74 ?? 49 83 8c 24 18 01 00 00 ?? 49 69 4c 24 30 ?? ?? ?? ?? 49 8b 84 24 ?? ?? ?? ?? 48 83 c3 04 48 35 ?? ?? ?? ?? 49 89 44 24 40 41 8b 84 24 ?? ?? ?? ?? 41 01 84 24 ?? ?? ?? ?? 49 8b 04 24 48 89 48 30 48 81 fb ?? ?? ?? ?? 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_MER_2147834367_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MER!MTB"
        threat_id = "2147834367"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 ff c2 48 8b 43 ?? 0f b6 14 0a 41 32 54 01 ff 48 8b 83 ?? ?? ?? ?? 41 88 54 01 ff 48 8b 83 ?? ?? ?? ?? 48 8b 93 ?? ?? ?? ?? 48 8b 88 ?? ?? ?? ?? 48 81 f1 75 0e 00 00 48 29 8a d8 00 00 00 33 d2 4c 8b 83 ?? ?? ?? ?? 48 63 8b ?? ?? ?? ?? 48 81 c1 b6 eb ff ff 49 8b 80 ?? ?? ?? ?? 48 03 c1 48 63 4b ?? 48 f7 f1 49 63 c2 89 93 ?? ?? ?? ?? 49 8b 88 ?? ?? ?? ?? 48 81 c1 a3 3a 00 00 48 3b c1 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_AUS_2147834375_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.AUS!MTB"
        threat_id = "2147834375"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 8b 0c 00 33 8f ?? ?? ?? ?? 48 8b 87 ?? ?? ?? ?? 41 89 0c 00 48 8d 0d ?? ?? ?? ?? 48 c7 c0 ?? ?? ?? ?? 48 2b c1 48 01 87 ?? ?? ?? ?? 48 8b 87 ?? ?? ?? ?? 48 39 47 40 77}  //weight: 1, accuracy: Low
        $x_1_2 = {ff c6 01 87 ?? ?? ?? ?? 49 83 c0 04 48 8b 47 ?? 8b 50 ?? 41 2b d1 48 63 c6 48 c1 ea 02 48 3b c2 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_KA_2147834447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.KA!MTB"
        threat_id = "2147834447"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 8b c8 41 8b d2 d3 ea 8a 08 48 8b 47 ?? 80 f1 ?? 22 d1 48 63 8f ?? ?? ?? ?? 88 14 01 ff 87 ?? ?? ?? ?? 45 85 c0 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_KA_2147834447_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.KA!MTB"
        threat_id = "2147834447"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 b9 40 00 00 00 48 8b 4d 30 41 b8 00 30 00 00 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {8b 13 8b 4b f8 49 ?? ?? 44 8b 43 fc 48 03 ce e8 ?? ?? ?? ?? 0f b7 45 06 48 8d 5b 28 ff c7 3b f8 7c}  //weight: 1, accuracy: Low
        $x_1_3 = {0f 10 02 42 0f 10 4c 02 f0 0f 11 01 42 0f 11 4c 01 f0 48 8b c1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_KK_2147834500_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.KK!MTB"
        threat_id = "2147834500"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 b9 04 00 00 00 41 b8 00 30 00 00 48 89 c2 b9 00 00 00 00 48 8b ?? ?? ?? ?? ?? ff}  //weight: 1, accuracy: Low
        $x_1_2 = "Loader.nim" ascii //weight: 1
        $x_1_3 = "bcmode.nim" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_KK_2147834500_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.KK!MTB"
        threat_id = "2147834500"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b8 93 24 49 92 41 f7 e8 41 03 d0 c1 fa 05 8b c2 c1 e8 1f 03 d0 41 8b c0 41 ff c0 6b d2 38 2b c2 48 63 c8 48 8d 05 b4 20 02 00 8a 04 01 42 32 04 0e 41 88 01 49 ff c1 44 3b c5 72 c4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_KK_2147834500_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.KK!MTB"
        threat_id = "2147834500"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff c0 89 44 24 ?? 8b 44 24 ?? 39 44 24 04 73 ?? 8b 44 24 ?? 99 81 e2 ?? ?? ?? ?? 03 c2 25 ?? ?? ?? ?? 2b c2 88 04 24 8b 44 24 ?? 0f b6 0c 24 48 8b 54 24 ?? 0f be 04 02 33 c1 8b 4c 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_KB_2147834501_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.KB!MTB"
        threat_id = "2147834501"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 f8 08 02 00 00 41 b8 00 30 00 00 33 c9 8b d7 8b f7 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {41 b8 00 30 00 00 8b 10 83 41 08 fc 89 51 14 33 c9 44 8d 49 04 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {c5 fd 7f 41 60 c5 fd 7f 81 80 00 00 00 c5 fd 7f 81 a0 00 00 00 c5 fd 7f 81 c0 00 00 00 c5 fd 7f 81 e0 00 00 00 48 81 c1 00 01 00 00 49 81 e8 00 01 00 00 49 81 f8 00 01 00 00 73 b6}  //weight: 1, accuracy: High
        $x_1_4 = {41 b9 00 30 00 00 4c 89 65 a0 c7 44 24 20 40 00 00 00 ff 15 ?? ?? 00 00 48 8b f8 48 85 c0 75 2b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_COM_2147834655_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.COM!MTB"
        threat_id = "2147834655"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c0 01 89 84 24 ?? ?? ?? ?? 8b 84 24 ?? ?? ?? ?? 39 84 24 ?? ?? ?? ?? 73 ?? 48 63 8c 24 ?? ?? ?? ?? 48 8b 44 24 ?? 44 0f b6 04 08 8b 84 24 ?? ?? ?? ?? 99 b9 ?? ?? ?? ?? f7 f9 48 63 ca 48 8b 44 24 ?? 0f b6 04 08 41 8b d0 33 d0 48 63 8c 24 ?? ?? ?? ?? 48 8b 44 24 ?? 88 14 08 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_RA_2147834740_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.RA!MTB"
        threat_id = "2147834740"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 63 c6 48 8b 4d 88 0f b6 4c 08 01 30 4c 15 50 c6 44 24 7c 00 48 8d 55 e0 48 8d 4c 24 7c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_RA_2147834740_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.RA!MTB"
        threat_id = "2147834740"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 ee c1 fa 03 8b c2 c1 e8 1f 03 d0 8b c6 ff c6 6b d2 21 2b c2 48 63 c8 48 8d 05 ?? ?? ?? ?? 8a 04 01 43 32 04 01 41 88 00 49 ff c0 3b f7 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_RA_2147834740_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.RA!MTB"
        threat_id = "2147834740"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 ed 2b d5 c1 fa 04 8b c2 c1 e8 1f 03 d0 48 63 c5 83 c5 01 48 63 ca 48 6b c9 1c 48 03 c8 48 8b 44 24 ?? 42 8a 8c 39 ?? ?? ?? ?? 41 32 0c 00 41 88 0c 18 49 83 c0 01 3b 6c 24 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_TY_2147835072_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.TY!MTB"
        threat_id = "2147835072"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {b8 f7 34 c2 72 49 83 c0 01 f7 ee 2b d6 c1 fa 05 8b c2 c1 e8 1f 03 d0 48 63 c6 83 c6 01 48 63 ca 48 6b c9 3a 48 03 c8 42 0f b6 04 11 43 32 44 01 ff 41 88 40 ff 3b 74 24 20 72 c5}  //weight: 2, accuracy: High
        $x_1_2 = "Test.dll" ascii //weight: 1
        $x_1_3 = "BWQ81H7" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_TYY_2147835463_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.TYY!MTB"
        threat_id = "2147835463"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 e8 0f 89 c0 8b 44 84 60 c1 e8 03 31 c1 41 01 c8 8b 44 24 0c 83 e8 10 89 c0 44 03 44 84 60 8b 44 24 0c 44 89 44 84 60 c7 44 24 18 a9 8a 8d 96 c7 44 24 14 8a 8a b4 19 c7 44 24 10 31 7c 58 78 e9 ac 02 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "\\.\\PhysicalDrive0" ascii //weight: 1
        $x_1_3 = "QjZsu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_TYZ_2147835464_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.TYZ!MTB"
        threat_id = "2147835464"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {b8 09 cb 3d 8d 41 f7 e0 c1 ea 05 0f be c2 6b c8 3a 41 8a c0 41 ff c0 2a c1 04 36 41 30 01 49 ff c1 41 83 f8 18 7c d9}  //weight: 2, accuracy: High
        $x_2_2 = {8b c6 41 f7 e0 c1 ea 05 0f be c2 6b c8 3a 41 8a c0 2a c1 04 36 41 30 01 44 03 c3 4c 03 cb 41 83 f8 15 7c dc}  //weight: 2, accuracy: High
        $x_1_3 = "JMOZPmLP4$" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_CobaltStrike_DHO_2147835804_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.DHO!MTB"
        threat_id = "2147835804"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {41 0f b6 44 0f ?? 30 01 48 ff c1 48 83 ea 01 75 ?? 49 83 e8 01 75}  //weight: 2, accuracy: Low
        $x_2_2 = {41 0f b6 0c 00 30 08 48 ff c0 48 83 ea 01 75 ?? 49 83 e9 01 75}  //weight: 2, accuracy: Low
        $x_1_3 = "\\projects\\garda\\storage\\targets\\work6.x2.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_GFT_2147835874_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.GFT!MTB"
        threat_id = "2147835874"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {48 8b 00 48 03 44 24 28 48 89 84 24 88 00 00 00 48 8b 84 24 88 00 00 00 0f b6 00 0f b6 4c 24 20 33 c1 89 44 24 30 0f b6 44 24 30 88 44 24 21 48 8d 44 24 21 48 89 84 24}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_GFT_2147835874_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.GFT!MTB"
        threat_id = "2147835874"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f c9 49 8d 8c 24 12 08 43 f3 41 0f 92 c1 8a 4c 24 07 44 8b cc eb 28 00 8b 1b 7e 8d 62 ae b9 ?? ?? ?? ?? d1 4a 8d 34 bd 00 00 00 00 44 89 4c 24 09 44 8b 4c 24 0e 87 4c 24 07 4c 87 ce eb bd}  //weight: 2, accuracy: Low
        $x_2_2 = {00 01 00 b1 54 01 00 19 2d ?? ?? ?? ?? 01 00 d1 a8 01 00 56 1a 15 ?? ?? ?? ?? 00 77 76 01 00 30 75 01 00 d4 bc ?? ?? ?? ?? 01 00 7a 99}  //weight: 2, accuracy: Low
        $x_1_3 = ".sedata" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_CobaltStrike_GFF_2147835875_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.GFF!MTB"
        threat_id = "2147835875"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 44 24 28 40 00 00 00 c7 44 24 20 00 10 00 00 31 db 48 8d ?? ?? ?? 4c 8d 4c ?? ?? 48 89 f9 45 31 c0 ff d6}  //weight: 1, accuracy: Low
        $x_1_2 = {f3 0f 6f 0a f3 42 0f 6f 54 02 f0 f3 0f 7f 09 f3 42 0f 7f 54 01 f0 c3}  //weight: 1, accuracy: High
        $x_1_3 = ".gehc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_LT_2147835941_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.LT!MTB"
        threat_id = "2147835941"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 b9 40 00 00 00 41 b8 00 30 00 00 ba ?? ?? ?? ?? b9 00 00 00 00 48 8b 05 ?? ?? ?? ?? ff}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 08 8b 85 ?? ?? ?? ?? 48 98 0f b6 54 05 ba 8b 85 ?? ?? ?? ?? 4c 63 c0 48 8b 85 ?? ?? ?? ?? 4c 01 c0 31 ca 88 10 83 85 ?? ?? ?? ?? 01 83 85 ?? ?? ?? ?? 01 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_II_2147836293_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.II!MTB"
        threat_id = "2147836293"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c3 48 8b 54 24 20 88 04 0a eb df eb ef 89 04 24 8b 44 24 28 eb db 48 83 ec 18 c7 04 24 00 00 00 00 eb ed eb c5 48 8b 4c 24 30}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_II_2147836293_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.II!MTB"
        threat_id = "2147836293"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 04 24 ff c0 89 04 24 8b 44 24 ?? 39 04 24 73 ?? 8b 04 24 0f b6 4c 24 ?? 48 8b 54 24 ?? 0f be 04 02 33 c1 8b 0c 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_KG_2147836389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.KG!MTB"
        threat_id = "2147836389"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c0 01 89 85 ec fe ff ff eb ?? 8b 85 ?? ?? ?? ?? 48 63 c0 48 8d 0d 0a 1f 10 00 48 01 c1 8b 85 ?? ?? ?? ?? 48 63 c0 48 c1 e0 02 48 8d 15 cb 0e 00 00 48 01 c2 0f b6 02 88 01 eb bb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_WW_2147836390_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.WW!MTB"
        threat_id = "2147836390"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f3 0f 7f 4c 18 10 f3 0f 6f 44 18 20 66 0f 6f ca 66 0f fc c8 f3 0f 7f 4c 18 20 f3 0f 6f 44 18 30 66 0f 6f ca 66 0f fc c8 f3 0f 7f 4c 18 30 48 83 c0 40 48 3d 00 04 04 00 7c a6}  //weight: 1, accuracy: High
        $x_1_2 = "Release\\movenpeak.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_NP_2147836391_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.NP!MTB"
        threat_id = "2147836391"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_ZSt11__addressofI13_STARTUPINFOAEPT_RS1_" ascii //weight: 1
        $x_1_2 = "_Z11RunThatShitv" ascii //weight: 1
        $x_1_3 = "_ZSt9addressofI13_STARTUPINFOAEPT_RS1_" ascii //weight: 1
        $x_1_4 = "Shellcode injected" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_AWV_2147836671_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.AWV!MTB"
        threat_id = "2147836671"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 b9 40 00 00 00 41 b8 00 10 00 00 48 8b d6 33 c9 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {f3 0f 6f 41 f0 66 0f 6f ca 66 0f ef c8 f3 0f 7f 49 f0 f3 0f 6f 01 66 0f 6f ca 66 0f ef c8 f3 0f 7f 09 f3 0f 6f 41 10 66 0f ef c2 f3 0f 7f 41 10 83 c2 40 48 8d 49 40 49 8d 04 08 49 3b c1 7c b2}  //weight: 1, accuracy: High
        $x_1_3 = "LockDownProtectProcessById" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_RK_2147836744_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.RK!MTB"
        threat_id = "2147836744"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Go build ID:" ascii //weight: 1
        $x_1_2 = "0cobaltstrike-chtsec" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_RK_2147836744_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.RK!MTB"
        threat_id = "2147836744"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Attempting Thread Hijacking into" ascii //weight: 1
        $x_1_2 = "Attempting APC Injection into" ascii //weight: 1
        $x_1_3 = "shellcode injection into" ascii //weight: 1
        $x_1_4 = "Attempting Hollowing with IAT" ascii //weight: 1
        $x_1_5 = "Attempting Process Doppelg" ascii //weight: 1
        $x_1_6 = "PPID Spoofing" ascii //weight: 1
        $x_1_7 = "Shellcode payload detected" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win64_CobaltStrike_GYZ_2147836745_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.GYZ!MTB"
        threat_id = "2147836745"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 f7 e0 41 8b c0 2b c2 d1 e8 03 c2 c1 e8 ?? 0f be c0 6b c8 ?? 41 8a c0 41 ff c0 2a c1 04 ?? 41 30 01 49 ff c1 41 83 f8 ?? 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_GY_2147836750_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.GY!MTB"
        threat_id = "2147836750"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 41 f7 e0 c1 ea 04 0f be c2 6b c8 ?? 41 8a c0 2a c1 04 ?? 41 30 01 44 03 c3 4c 03 cb 41 83 f8 0d 7c dc}  //weight: 1, accuracy: Low
        $x_1_2 = {45 33 c0 4c 8d 4c 24 20 b8 ?? ?? ?? ?? 41 f7 e0 c1 ea 04 0f be c2 6b c8 ?? 41 8a c0 41 ff c0 2a c1 04 ?? 41 30 01 49 ff c1 41 83 f8 18 7c d9}  //weight: 1, accuracy: Low
        $x_1_3 = {4c 8d 4c 24 50 be ?? ?? ?? ?? 41 8d 5f 01 8b c6 41 f7 e0 c1 ea ?? 0f be c2 6b c8 ?? 41 8a c0 2a c1 04 ?? 41 30 01 44 03 c3 4c 03 cb 41 83 f8 15 7c dc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_CobaltStrike_BE_2147837216_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.BE!MTB"
        threat_id = "2147837216"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 c1 83 e1 ?? 8a 0c 0a 41 ?? ?? ?? 48 ?? ?? 48 ?? ?? ?? 75 ?? 31 c0 41 ?? ?? 7e ?? 48 ?? ?? 83 e1 ?? 8a 0c 0a 41 ?? ?? ?? 48 ?? ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_BE_2147837216_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.BE!MTB"
        threat_id = "2147837216"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f7 eb 03 d3 c1 fa 04 8b c2 c1 e8 1f 03 d0 6b c2 1f 2b c8 8d 04 0b 48 98 42 0f b6 14 18 41 8d 04 18 41 32 56 ff ff c3 48 63 c8 88 14 39 8b 94 24 98 00 00 00 41 03 d2 3b da 72}  //weight: 1, accuracy: High
        $x_1_2 = "_$GXo>E?ACaHjF>ogYGSiaU8lJltUi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_VM_2147837268_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.VM!MTB"
        threat_id = "2147837268"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DetectAttack.dll" ascii //weight: 1
        $x_1_2 = "?AVpairNode@@" ascii //weight: 1
        $x_1_3 = "x64\\Debug\\DetectAttack.pdb" ascii //weight: 1
        $x_1_4 = "send() detoured successfully" ascii //weight: 1
        $x_1_5 = "beacon.dll" ascii //weight: 1
        $x_1_6 = "powershell -nop -exec bypass -EncodedCommand" ascii //weight: 1
        $x_1_7 = "m already in SMB mode" ascii //weight: 1
        $x_1_8 = "is an x64 process (can't inject x86 content)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win64_CobaltStrike_CB_2147837406_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CB!MTB"
        threat_id = "2147837406"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 c3 31 c0 39 c6 7e ?? 48 89 c2 83 e2 ?? 8a 54 15 ?? 32 14 07 88 14 03 48 ff c0 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CB_2147837406_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CB!MTB"
        threat_id = "2147837406"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0f 57 c2 0f 57 ca f3 0f 7f 40 ?? f3 0f 6f 44 10 ?? f3 0f 7f 48 ?? 0f 57 c2 f3 0f 6f 4c 08 ?? f3 0f 7f 40 ?? 0f 57 ca f3 0f 7f 48 ?? 49 83 e9 01 75}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CB_2147837406_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CB!MTB"
        threat_id = "2147837406"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c8 8b 43 ?? 31 8b ?? ?? ?? ?? 8b 8b ?? ?? ?? ?? 2b 4b ?? 81 f1 ?? ?? ?? ?? 0f af c1 48 8b 8b ?? ?? ?? ?? 89 43 ?? 8b 43 ?? 31 04 11 48 83 c2 ?? 8b 83 ?? ?? ?? ?? 01 43 ?? 48 81 fa ?? ?? ?? ?? 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CB_2147837406_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CB!MTB"
        threat_id = "2147837406"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MyTestMutex1" ascii //weight: 1
        $x_1_2 = "CreateMutexA" ascii //weight: 1
        $x_1_3 = "o1uhb2bUFWqHTURnFSHrGsn" ascii //weight: 1
        $x_1_4 = "OpenMutexA" ascii //weight: 1
        $x_1_5 = "KSPKUpwR9Ng1hurnkYp9BIhHX2Rubjtj" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_KKM_2147837438_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.KKM!MTB"
        threat_id = "2147837438"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b 43 78 2b 83 d0 00 00 00 01 43 20 b8 ?? ?? ?? ?? 2b 43 4c 89 83 04 01 00 00 8b 4b 20 8b 83 98 00 00 00 ff c1 0f af c1 89 83 98 00 00 00 49 81 f9 ?? ?? ?? ?? 0f 8c}  //weight: 1, accuracy: Low
        $x_1_2 = "nfvurg856lk63.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_SPL_2147837728_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.SPL!MTB"
        threat_id = "2147837728"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "programdata\\3bef479.tmp" ascii //weight: 1
        $x_1_2 = "Release\\SetupEngine.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_SPL_2147837728_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.SPL!MTB"
        threat_id = "2147837728"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {8b 05 e8 b1 02 00 8d 48 01 0f af c8 83 e1 01 74 7c 48 8b 85 50 01 00 00 48 8b 00 48 8b 8d f0 00 00 00 48 89 01 48 8b 85 50 01 00 00 48 8b 8d f0 00 00 00 48 8b 09 48 63 49 3c 48 03 08 48 8b 85 38 01 00 00 48 89 08 48 8b 85 38 01 00 00 48 8b 00 8b 50 50 48 83 ec 20 31 c9 41 b8 00 30 00 00 41 b9 04 00 00 00 ff 15 [0-4] 48 83 c4 20 48 8b 8d 60 01 00 00 48 89 01 48 8b 85 60 01 00 00 48 8b 00 48 89 45 50 e9}  //weight: 6, accuracy: Low
        $x_1_2 = "Applebaidugooglebingcsdnbokeyuanhelloworld.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_SPA_2147837729_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.SPA!MTB"
        threat_id = "2147837729"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 eb 8b cb ff c3 c1 ?? ?? 8b c2 c1 ?? ?? 03 d0 6b ?? ?? [0-16] 0f b6 8c 3a ?? ?? ?? ?? 41 32 4c ?? ?? 43 88 4c 08 ?? 3b 5c 24 20 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_BG_2147837925_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.BG!MTB"
        threat_id = "2147837925"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 8b 8b e8 00 00 00 8b 83 80 00 00 00 42 31 04 09 49 83 c1 04 8b 8b f4 00 00 00 01 8b 80 00 00 00 8b 4b 10 29 8b 88 00 00 00 8b 8b 88 00 00 00 81 c1 ba c5 1a 00 31 8b b4 00 00 00 49 81 f9 20 df 01 00 7c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_MWQ_2147837946_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MWQ!MTB"
        threat_id = "2147837946"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 03 c1 41 81 e0 ?? ?? ?? ?? 7d ?? 41 ff c8 41 81 c8 ?? ?? ?? ?? 41 ff c0 49 63 c0 49 ff c3 0f b6 0c 04 42 32 4c 1f ?? 48 ff cb 41 88 4b ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_BH_2147838043_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.BH!MTB"
        threat_id = "2147838043"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 44 3e 10 8a 44 05 10 88 44 3b 10 48 ff c7 eb}  //weight: 1, accuracy: High
        $x_1_2 = {49 8b 14 24 48 39 d7 72 ?? 48 ff ca eb ?? 48 83 ca ff 48 89 f9 e8 [0-4] 8a 44 33 10 41 88 44 3c 10 48 83 c7 01 71 ?? e8 [0-4] 48 83 c6 01 71 ?? e8 [0-4] 48 3b 2b 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_LJ_2147838049_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.LJ!MTB"
        threat_id = "2147838049"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {b9 60 ea 00 00 ff d3 eb f7}  //weight: 10, accuracy: High
        $x_1_2 = "temp.dll" ascii //weight: 1
        $x_1_3 = "StartW" ascii //weight: 1
        $x_1_4 = "DllMain" ascii //weight: 1
        $x_1_5 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_CobaltStrike_GCE_2147838179_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.GCE!MTB"
        threat_id = "2147838179"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 04 11 48 83 c2 04 8b 43 3c 35 ?? ?? ?? ?? 29 43 38 8b 43 38 2b 43 68 35 ?? ?? ?? ?? 01 43 1c 8b 83 ?? ?? ?? ?? 01 83 ?? ?? ?? ?? 48 81 fa ?? ?? ?? ?? 7c}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_HMM_2147838326_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.HMM!MTB"
        threat_id = "2147838326"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff c8 83 c8 ?? ff c0 41 03 c3 41 ff c6 48 63 c8 48 8b 44 24 ?? 0f b6 8c 31 ?? ?? ?? ?? 41 32 0c 02 41 88 0c 1a 49 ff c2 44 3b 74 24 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_HMN_2147838329_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.HMN!MTB"
        threat_id = "2147838329"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c2 c1 e8 ?? 03 d0 6b c2 ?? 41 8b c8 2b c8 48 63 d1 48 8b 45 ?? 0f b6 8c 32 ?? ?? ?? ?? 41 32 0c 01 41 88 0c 19 41 ff c0 4d 8d 49 ?? 44 3b 45 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_SAA_2147838340_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.SAA!MTB"
        threat_id = "2147838340"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ca 81 e1 ?? ?? ?? ?? 7d ?? ff c9 83 c9 ?? ff c1 48 ?? ?? 48 ?? ?? ?? 0f b6 8c 31 ?? ?? ?? ?? 41 ?? ?? ?? 41 ?? ?? ?? ff c2 49 ?? ?? 3b 55 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_TS_2147838424_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.TS!MTB"
        threat_id = "2147838424"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 8b ca 41 8b d3 d3 ea 8a 08 48 8b 46 ?? 80 f1 ?? 22 d1 48 63 8e ?? ?? ?? ?? 88 14 01 ff 86 ?? ?? ?? ?? 48 8b 86 ?? ?? ?? ?? 48 8b 8e ?? ?? ?? ?? 4c 31 76 ?? 48 0b cf 48 81 76 ?? ?? ?? ?? ?? 48 0f af c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_LKC_2147838726_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.LKC!MTB"
        threat_id = "2147838726"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 83 e1 1f 49 83 e9 20 49 2b c9 49 2b d1 4d 03 c1 49 81 f8 00 01 00 00 0f 86 a3 00 00 00 49 81 f8 00 00 18 00 0f 87 3e 01 00 00 [0-25] c5 fe 6f 0a c5 fe 6f 52 20 c5 fe 6f 5a 40 c5 fe 6f 62 60 c5 fd 7f 09 c5 fd 7f 51 20 c5 fd 7f 59 40 c5 fd 7f 61 60}  //weight: 1, accuracy: Low
        $x_1_2 = {41 b9 40 00 00 00 41 b8 00 30 00 00 48 ?? ?? ?? 30 33 c9 e8}  //weight: 1, accuracy: Low
        $x_1_3 = "Sdrpst" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_LKD_2147838727_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.LKD!MTB"
        threat_id = "2147838727"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 fa 04 8b c2 c1 e8 1f 03 d0 8b c5 ff c5 6b d2 42 2b c2 48 63 c8 48 ?? ?? ?? ?? 42 ?? ?? ?? ?? ?? ?? 00 00 41 ?? ?? ?? ?? 41 ?? ?? ?? ?? 3b 6c 24 60 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_LKE_2147838991_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.LKE!MTB"
        threat_id = "2147838991"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 ed c1 fa 05 8b c2 c1 e8 ?? 03 d0 8b c5 ff c5 6b ?? ?? 2b c2 48 63 c8 48 8b 44 24 38 42 ?? ?? ?? ?? ?? ?? ?? 41 32 ?? ?? 41 88 ?? ?? 49 ?? ?? 3b ?? ?? 30 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_NEAB_2147839124_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.NEAB!MTB"
        threat_id = "2147839124"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {2b c1 48 63 c8 48 8b 44 24 68 42 8a 8c 31 30 49 00 00 41 32 0c 00 41 88 0c 18 49 ff c0 3b 6c 24 60 72 c2}  //weight: 10, accuracy: High
        $x_5_2 = "http://msun.ru" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_LKF_2147839210_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.LKF!MTB"
        threat_id = "2147839210"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 8c 24 d8 00 00 00 0f b6 04 01 8b 4c 24 7c 33 c8 8b c1 48 63 4c 24 60 48 8b 54 24 70 88 04 0a e9 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_LKG_2147839492_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.LKG!MTB"
        threat_id = "2147839492"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 47 58 48 81 c9 2b 4b 00 00 48 0f af c1 48 89 47 58 b8 c1 41 00 00 48 2b 87 18 01 00 00 48 01 87 80 00 00 00 45 85 c9}  //weight: 1, accuracy: High
        $x_1_2 = {48 31 4e 58 41 8b c9 d3 ea 8a 48 40 48 8b 46 20 80 f1 a0 22 d1 48 63 8e 10 01 00 00 88 14 01 ff 86 10 01 00 00 45 85 c9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_CobaltStrike_LKH_2147839493_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.LKH!MTB"
        threat_id = "2147839493"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {75 18 48 8b 44 24 68 48 8b 4c 24 10 48 89 08 48 8b 44 24 70 8b 4c 24 18 89 08 48 8b 04 24 48 83 c0 28 48 89 04 24 e9 56 ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_BJ_2147839631_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.BJ!MTB"
        threat_id = "2147839631"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 c9 4d 8d 40 01 49 83 f9 64 49 0f 45 c9 0f b6 44 0c 30 41 30 40 ff 33 c0 49 83 f9 64 4c 8d 49 01 0f 45 c2 41 ff c2 8d 50 01 41 81 fa [0-4] 72}  //weight: 2, accuracy: Low
        $x_2_2 = "McVsoCfgGetObject" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_BJ_2147839631_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.BJ!MTB"
        threat_id = "2147839631"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 2b 3f 02 00 2b 85 ?? ?? ?? ?? 8b 95 ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? 48 ?? 48 ?? ?? ?? ?? ?? ?? 0f b6 04 08 88 02 83 85 ?? ?? ?? ?? ?? 81 bd}  //weight: 1, accuracy: Low
        $x_1_2 = {44 0f b6 04 10 8b 85 ?? ?? ?? ?? 48 ?? 48 ?? ?? ?? ?? ?? ?? 0f b6 0c 10 8b 85 ?? ?? ?? ?? 48 ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? 44 ?? ?? 31 ca 88 10 83 85 ?? ?? ?? ?? ?? 83 bd}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_AA_2147839904_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.AA!MTB"
        threat_id = "2147839904"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c2 c1 e8 ?? 03 d0 8b c5 ff c5 6b d2 ?? 2b c2 48 63 c8 48 8b 44 24 [0-2] 42 0f b6 8c 39 ?? ?? ?? ?? 41 32 4c 00 ff 41 88 4c 18 ff 3b 6c 24 ?? 72 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_SH_2147840252_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.SH!MTB"
        threat_id = "2147840252"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 63 44 24 20 48 8d 0d d0 11 00 00 0f be 04 01 89 44 24 24 8b 44 24 20 99 83 e0 01 33 c2 2b c2 48 98 48 8b 4c 24 38 0f be 04 01 8b 4c 24 24 33 c8 8b c1 48 63 4c 24 20 48 8b 54 24 30 88 04 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_SH_2147840252_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.SH!MTB"
        threat_id = "2147840252"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b c1 01 83 ?? ?? ?? ?? 49 ?? ?? ?? 48 ?? ?? ?? 48 33 00 8b 4b ?? 35 ?? ?? ?? ?? 29 43 ?? 33 4b ?? 48 ?? ?? ?? ?? ?? ?? 41 ?? ?? ?? b8 ?? ?? ?? ?? 0f af 53}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_NEAD_2147840318_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.NEAD!MTB"
        threat_id = "2147840318"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {41 0f b6 04 10 88 02 48 ff c2 8b 43 54 48 8b ca 49 2b ce 48 3b c8 72 e8}  //weight: 10, accuracy: High
        $x_2_2 = "MeterpreterLoaded" ascii //weight: 2
        $x_2_3 = "CymulateStagelessMeterpreterDll.dll" ascii //weight: 2
        $x_2_4 = "\\Cymulate\\Agent\\AttacksLogs\\edr" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_LKJ_2147840331_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.LKJ!MTB"
        threat_id = "2147840331"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 ea 08 88 14 01 ff 43 74 8b 83 88 00 00 00 48 63 53 74 48 8b 8b b0 00 00 00 01 83 fc 00 00 00 44 88 04 0a b9 75 cd 19 00 2b 8b a0 00 00 00 ff 43 74 89 4b 18 49 81 f9 10 14 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_SF_2147840335_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.SF!MTB"
        threat_id = "2147840335"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 04 24 ff c0 89 04 24 8b 44 24 ?? 39 04 24 73 ?? 8b 04 24 0f b6 4c 24 ?? 48 ?? ?? ?? ?? 0f be 04 02 33 c1 8b 0c 24 48 ?? ?? ?? ?? 88 04 0a eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_LKK_2147840341_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.LKK!MTB"
        threat_id = "2147840341"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SdJFlskdjf" ascii //weight: 1
        $x_1_2 = {ba 0c 00 00 f0 00 00 00 00 00 00 ?? ?? 0b 00 00 10 00 00 00 00 00 80 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_MW_2147840661_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MW!MTB"
        threat_id = "2147840661"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 63 d8 48 69 f3 ?? ?? ?? ?? 48 89 f1 48 c1 e9 ?? 48 c1 fe ?? 01 ce c1 e6 ?? 8d 0c b6 29 cb 48 63 cb 42 0f b6 0c 01 32 0c 02 88 0c 07 48 ff c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_MW_2147840661_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MW!MTB"
        threat_id = "2147840661"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 44 24 60 48 63 48 04 f6 44 0c 70 06 75 48 33 c9 ff 15 ?? ?? ?? ?? 41 b9 40 00 00 00 41 b8 00 30 00 00 48 8b d6 33 c9 ff 15 ?? ?? ?? ?? 48 8b d8 4c 8b c6 48 8b d5 48 8b c8 e8 ?? ?? ?? ?? 45 33 c0 48 8b d3 33 c9 ff 15 ?? ?? ?? ?? 48 8b c8 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_MW_2147840661_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MW!MTB"
        threat_id = "2147840661"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {29 e8 01 f8 01 c1 48 8d 05 ?? ?? ?? ?? 44 29 c9 44 01 d1 41 01 cb 41 29 eb 41 01 fb 4d 63 db 42 32 14 18 48 8b 44 24 50 42 88 14 20 48 8b 44 24 30 48 39 44 24 40 4c 8d 60 01 0f 87}  //weight: 5, accuracy: Low
        $x_2_2 = "ABPNRwDugvreFKKTXmCAf" ascii //weight: 2
        $x_2_3 = "ABgGMbUEPdcarb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_MA_2147840702_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MA!MTB"
        threat_id = "2147840702"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {f7 ee ff c6 c1 fa 03 8b c2 c1 e8 1f 03 d0 6b c2 11 2b c8 48 63 c1 48 8d 0d ?? ?? ?? ?? 8a 04 08 43 32 04 02 41 88 00 49 ff c0 3b f3 72 cb}  //weight: 5, accuracy: Low
        $x_2_2 = "DllRegisterServer" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_MA_2147840702_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MA!MTB"
        threat_id = "2147840702"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f af 48 68 8b c1 89 44 24 34 8b 44 24 34 c1 e8 10 48 8b 8c 24 [0-4] 48 63 49 6c 48 8b 94 24 [0-4] 48 8b 92 a0 00 00 00 88 04 0a 48 8b 84 24 [0-4] 8b 40 6c ff c0 48 8b 8c 24 [0-4] 89 41 6c 8b 44 24 34 c1 e8 08}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_SJ_2147840726_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.SJ!MTB"
        threat_id = "2147840726"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 ca 41 33 91 ?? ?? ?? ?? 81 f1 ?? ?? ?? ?? 41 ?? ?? ?? ?? ?? ?? 81 f2 ?? ?? ?? ?? 41 ?? ?? ?? ?? ?? ?? 41 ?? ?? ?? ?? ?? ?? 41 ?? ?? ?? 41 ?? ?? ?? 41 ?? ?? ?? ?? ?? ?? 49 ?? ?? ?? ?? ?? ?? 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_MET_2147841296_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MET!MTB"
        threat_id = "2147841296"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 04 11 48 83 c2 ?? 8b 8b ?? ?? ?? ?? 8b 83 ?? ?? ?? ?? 03 c1 35 ?? ?? ?? ?? 29 43 ?? 8b 43 ?? 83 e8 ?? 01 43 ?? 8b 83 ?? ?? ?? ?? 33 c1 35 ?? ?? ?? ?? 29 83 ?? ?? ?? ?? 8b 83 ?? ?? ?? ?? 01 83 ?? ?? ?? ?? 8b 83 ?? ?? ?? ?? 29 43 ?? 48 81 fa ?? ?? ?? ?? 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_BO_2147841791_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.BO!MTB"
        threat_id = "2147841791"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 55 fc 48 8b 45 10 48 01 d0 0f b6 00 84 c0 74 2a 8b 45 fc 8d 50 01 89 55 fc 89 c2 48 8b 45 10 48 01 d0 0f b7 00 66 89 45 f6 0f b7 55 f6 8b 45 f8 c1 c8 08 01 d0 31 45 f8 eb}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_BO_2147841791_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.BO!MTB"
        threat_id = "2147841791"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 1f e8 ?? ?? ?? ?? 33 d2 48 98 48 2b f5 48 f7 f6 49 8b 07 fe c2 41 32 14 06 42 88 14 33 48 8b 0f 46 30 24 31 49 ff c6 49 8b 77 ?? 49 8b 2f 48 8b ce 48 2b cd 4c 3b f1 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_BO_2147841791_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.BO!MTB"
        threat_id = "2147841791"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Write shellcode to memory succeeded" ascii //weight: 1
        $x_1_2 = "Memory permissions changed successfully: PAGE_EXECUTE" ascii //weight: 1
        $x_1_3 = "Thread opened successfully" ascii //weight: 1
        $x_1_4 = {48 01 c8 88 10 8b 85 ?? ?? ?? ?? 89 c2 8b 85 ?? ?? ?? ?? 88 54 05 ?? 83 85 ?? ?? ?? ?? 01 eb 40 00 8b 95 ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 48 8b 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CPG_2147841799_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CPG!MTB"
        threat_id = "2147841799"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {43 8d 0c 08 0f be c9 6b d1 ?? 80 ?? ?? 41 30 10 49 ff c0 4b 8d 0c 01 48 81 ?? ?? ?? ?? ?? 72}  //weight: 5, accuracy: Low
        $x_1_2 = "CPlApplet" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_BP_2147841828_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.BP!MTB"
        threat_id = "2147841828"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 b8 27 25 34 34 29 23 2b 23 48 89 45 46 48 b8 2b 23 2f 35 2e 34 54 ae}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_BP_2147841828_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.BP!MTB"
        threat_id = "2147841828"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 f8 80 3c 06 ?? 74 ?? 0f b7 04 06 89 da 48 89 e9 ff c7 c1 ca ?? 01 d0 31 c3 e8 ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 c2 48 8b 4c 24 ?? 83 e2 ?? 41 8a 54 15 ?? 32 14 07 88 14 01 48 ff c0 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_BP_2147841828_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.BP!MTB"
        threat_id = "2147841828"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {44 8a 0c 10 45 88 c8 41 f6 d0 44 88 84 24 [0-4] 41 80 e0 ?? 44 88 84 24 [0-4] 41 80 e1 ?? 45 08 c8 44 88 84 24 [0-4] 41 80 f0 ?? 44 88 04 10 89 c8 83 c0 01 89 84 24 [0-4] 83 e9 ?? 89 8c 24 [0-4] 0f 92 c1 89 84 24 [0-4] 0f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_BQ_2147842006_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.BQ!MTB"
        threat_id = "2147842006"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 89 f1 44 32 0c 0f 44 88 0c 08 48 83 c1 ?? 39 cb 7f}  //weight: 1, accuracy: Low
        $x_1_2 = {41 8b 08 81 e2 ?? ?? ?? ?? 48 8d 04 13 4c 01 14 01 eb ?? 45 33 f6 41 8b d6 44 ?? ?? ?? 0f 86 ?? ?? ?? ?? 8b ca 03 d6 8a 04 29 88 04 19 3b 57 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_BQ_2147842006_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.BQ!MTB"
        threat_id = "2147842006"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f 10 33 48 8d 55 b0 48 8b cb e8 [0-4] b9 10 00 00 00 0f 1f 40 00 0f 1f 84 00 00 00 00 00 0f b6 04 1f 30 03 48 ff c3 48 83 e9 01 75}  //weight: 2, accuracy: Low
        $x_2_2 = {b9 0f 27 00 00 ff 15 [0-4] 4c 89 74 24 20 41 b9 f4 01 00 00 4c 8d 85 60 02 00 00 48 8b 54 24 60 48 8b cf}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_LL_2147842039_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.LL!MTB"
        threat_id = "2147842039"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4c 89 c0 48 8d 15 cf 77 07 00 83 e0 0f 8a 0c 02 48 8b 44 24 48 42 32 0c 00 42 88 0c 06 49 ff c0 eb d7}  //weight: 1, accuracy: High
        $x_1_2 = {65 48 8b 04 25 60 00 00 00 48 8b 40 18 48 89 cf 48 8b 58 10 48 89 de 48 8b 4b 60 48 89 fa}  //weight: 1, accuracy: High
        $x_1_3 = {0f be 11 84 d2 74 12 c1 c8 0d 80 fa 60 7e 03 83 ea 20 01 d0 48 ff c1 eb e7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_LIT_2147842113_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.LIT!MTB"
        threat_id = "2147842113"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 8b d6 48 2b d7 88 04 17 ff c1 8b c1 48 ff c7 25 03 00 00 80 7d ?? ff c8 83 c8 fc ff c0 48 98 8a 04 18 32 07 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_LIT_2147842113_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.LIT!MTB"
        threat_id = "2147842113"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 41 f7 f9 48 8d 05 ?? ?? ?? ?? 48 63 d2 8a 0c 10 ?? 8b 44 24 48 42 32 0c 00 42 88 0c 06 49 ff c0 eb}  //weight: 1, accuracy: Low
        $x_1_2 = "CheckMenuRadio" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_YL_2147842257_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.YL!MTB"
        threat_id = "2147842257"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f7 ea c1 fa 04 89 c8 c1 f8 1f 29 c2 89 d0 6b c0 36 29 c1 89 c8 48 63 d0 48 8b 85 d8 02 00 00 48 01 d0 0f b6 00 44 31 c8 41 88 00 83 85 e4 02 00 00 01 8b 95 e4 02 00 00 8b 85 74 02 00 00 39 c2 72 87}  //weight: 1, accuracy: High
        $x_1_2 = {48 89 e5 48 83 ec 20 c7 45 f4 60 00 00 00 8b 45 f4 65 48 8b 00 48 89 45 e8 48 8b 45 e8 48 89 45 f8 48 8b 45 f8 48 83 c4 20 5d c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_LKM_2147842283_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.LKM!MTB"
        threat_id = "2147842283"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "QlZylT5WMZcGIAyTUbSGnAerR.resources" ascii //weight: 1
        $x_1_2 = "New Project 2.exe" ascii //weight: 1
        $x_1_3 = "HbrZa8" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_SN_2147842367_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.SN!MTB"
        threat_id = "2147842367"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 cb 41 ff 40 ?? 81 f1 ?? ?? ?? ?? 0f af c1 41 ?? ?? ?? ?? ?? ?? 05 ?? ?? ?? ?? 41 ?? ?? ?? 41 ?? ?? ?? 35 ?? ?? ?? ?? 41 ?? ?? ?? 41 ?? ?? ?? 05 ?? ?? ?? ?? 41 ?? ?? ?? 49 ?? ?? ?? ?? ?? ?? 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CXM_2147842412_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CXM!MTB"
        threat_id = "2147842412"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c8 f7 ea 8d 04 0a 89 c2 c1 fa ?? 89 c8 c1 f8 ?? 29 c2 89 d0 c1 e0 ?? 29 d0 89 ca 29 c2 48 63 c2 48 03 85 ?? ?? ?? ?? 0f b6 00 44 31 c8 41 88 00 83 85 ?? ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 48 63 d0 48 8b 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_LKO_2147842430_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.LKO!MTB"
        threat_id = "2147842430"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 b9 40 00 00 00 41 b8 00 30 00 00 8b [0-8] e8}  //weight: 1, accuracy: Low
        $x_1_2 = {72 61 77 2e 67 69 74 68 75 62 75 73 65 72 63 6f 6e 74 65 6e 74 2e 63 6f 6d 2f 6b 6b 2d 65 63 68 6f 31 32 33 2f 61 6f 69 73 6e 64 6f 69 2f [0-31] 2e 70 6e 67}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_SPRY_2147842509_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.SPRY!MTB"
        threat_id = "2147842509"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {42 0f b6 54 37 10 49 8d 47 01 42 32 94 3b e8 03 00 00 42 88 14 36 83 e0 0f 49 83 c6 01 49 89 c7 4d 39 f5 7f 12 49 39 ee 0f 8c 80 fd ff ff e9 2b ff ff ff 0f 1f 40 00 48 85 c0 75 c4}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_AP_2147842520_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.AP!MTB"
        threat_id = "2147842520"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {46 0f b7 44 4c ?? 49 8b c1 41 23 c2 49 8b d5 49 3b c2 49 0f 43 c2 c0 e0 ?? 0f b6 c8 41 0f b7 c1 48 d3 ea 66 41 2b c3 66 41 23 d2 66 33 d0 66 41 33 d0 66 42 89 54 4c ?? 49 ff c1 49 83 f9 ?? 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_LKP_2147842684_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.LKP!MTB"
        threat_id = "2147842684"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4c 8b 03 b8 4f ec c4 4e 41 f7 e1 41 8b c1 c1 ea 02 41 ff c1 6b d2 0d 2b c2 8a 4c 18 18 42 30 0c 07 48 ff c7 45 3b cb 72 d7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_EAA_2147842739_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.EAA!MTB"
        threat_id = "2147842739"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {2b c1 48 8b 8b ?? ?? ?? ?? 33 43 08 35 ?? ?? ?? ?? 89 43 08 8b 83 ?? ?? ?? ?? 42 31 04 11 49 83 c2 04 8b 83 ?? ?? ?? ?? 01 83 ?? ?? ?? ?? 49 81 fa 98 e2 01 00 7c b0}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_MMX_2147842889_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MMX!MTB"
        threat_id = "2147842889"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 89 c8 89 c8 48 ff c1 4c 3b 44 24 ?? 4c 8b 54 24 ?? 73 ?? 99 41 f7 f9 48 8d 05 ?? ?? ?? ?? 48 63 d2 8a 04 10 48 8b 54 24 ?? 42 32 04 02 43 88 04 02 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_MMY_2147842890_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MMY!MTB"
        threat_id = "2147842890"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 89 c1 44 89 c0 49 ff c0 48 3b 4c 24 ?? 4c 8b 54 24 ?? 73 ?? 99 41 f7 f9 48 8d 05 ?? ?? ?? ?? 48 63 d2 8a 04 10 48 8b 54 24 ?? 32 04 0a 41 88 04 0a eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_SO_2147842908_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.SO!MTB"
        threat_id = "2147842908"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 14 01 41 ?? ?? 41 ?? ?? ?? 49 ?? ?? ?? 49 ?? ?? ?? ?? ?? ?? c1 ea ?? 88 14 01 41 ?? ?? ?? 41 ?? ?? ?? ?? ?? ?? 41 ?? ?? ?? ?? ?? ?? 41 ?? ?? ?? ?? ?? ?? 35 ?? ?? ?? ?? 41 ?? ?? ?? ?? ?? ?? 41 ?? ?? ?? 41 ?? ?? ?? 41 ?? ?? ?? 81 c1 ?? ?? ?? ?? 03 d1 0f af c2 41}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_GEO_2147842963_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.GEO!MTB"
        threat_id = "2147842963"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 89 c6 48 c1 ee ?? 48 89 c3 48 c1 eb ?? 4c 21 cb 42 8b 1c 13 41 33 1c b0 48 89 c6 48 c1 ee ?? 4c 21 de 41 33 1c b6 48 8d 72 ?? 4c 21 d8 41 33 1c 87 89 5a 1c 41 ff c4 48 89 fb 48 89 f2 44 3b a1 ?? ?? ?? ?? 0f 82}  //weight: 10, accuracy: Low
        $x_1_2 = ".retplne" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CXO_2147843045_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CXO!MTB"
        threat_id = "2147843045"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff c9 03 d1 45 8b 04 01 41 33 d2 8b 43 2c 49 83 c1 ?? 89 53 ?? 83 f0 ?? 01 83 ?? ?? ?? ?? 48 63 8b ?? ?? ?? ?? 44 0f af 43 ?? 48 8b 83 ?? ?? ?? ?? 41 8b d0 c1 ea ?? 88 14 01 ff 83 ?? ?? ?? ?? 48 63 8b ?? ?? ?? ?? 48 8b 83 ?? ?? ?? ?? 44 88 04 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_SPQ_2147843100_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.SPQ!MTB"
        threat_id = "2147843100"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 db ba 07 00 00 00 48 8b 0d ?? ?? ?? ?? ff 15 ?? ?? ?? ?? ff c3 81 fb 7b 03 00 00 72 e4 80 34 3e 05 ba 07 00 00 00 48 8b 0d ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 48 ff c6 48 81 fe 7b 03 00 00 72}  //weight: 2, accuracy: Low
        $x_2_2 = {ba 7b 03 00 00 33 c9 44 8d 49 40 41 b8 00 10 00 00 ff 15 ?? ?? ?? ?? 48 8b d8 48 85 c0 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_JL_2147843141_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.JL!MTB"
        threat_id = "2147843141"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {80 f2 1f 41 fe c0 88 14 01 41 0f b6 c8 42 8a 54 09 01 84 d2}  //weight: 2, accuracy: High
        $x_1_2 = {41 8b 41 24 49 03 c0 8b ca 0f b7 14 48 41 8b 49 1c 49 03 c8 8b 34 91 49 03 f0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_CobaltStrike_JL_2147843141_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.JL!MTB"
        threat_id = "2147843141"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 c2 83 e2 ?? 0f b6 14 17 32 14 03 41 88 54 05 ?? 48 83 c0 ?? 49 39 c6 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_ACL_2147843435_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.ACL!MTB"
        threat_id = "2147843435"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 8d 4c 24 38 ba ?? ?? ?? ?? 48 89 c1 41 b8 ?? ?? ?? ?? ff 16 89 c1 e8 ?? ?? ?? ?? 44 8a 63 58 41 83 f4 01 41 20 c4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_ACL_2147843435_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.ACL!MTB"
        threat_id = "2147843435"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 01 d0 0f b7 00 66 89 45 f6 0f b7 45 f6 8b 55 f8 c1 ca 08 01 d0 31 45 f8 8b 45 fc 48 8b 55 10 48 01 d0 0f b6 00 84 c0}  //weight: 1, accuracy: High
        $x_1_2 = {c6 45 c0 41 c6 45 c1 6f c6 45 c2 66 c6 45 c3 6e c6 45 c4 49 c6 45 c5 72 c6 45 c6 61 c6 45 c7 64 c6 45 c8 6e c6 45 c9 65 c6 45 ca 6c c6 45 cb 61 c6 45 cc 43 c6 45 cd 6d c6 45 ce 75 c6 45 cf 6e c6 45 d0 45}  //weight: 1, accuracy: High
        $x_1_3 = {c6 85 45 1f 00 00 74 c6 85 46 1f 00 00 63 c6 85 47 1f 00 00 65 c6 85 48 1f 00 00 74 c6 85 49 1f 00 00 6f c6 85 4a 1f 00 00 72 c6 85 4b 1f 00 00 50 c6 85 4c 1f 00 00 6c c6 85 4d 1f 00 00 61 c6 85 4e 1f 00 00 75 c6 85 4f 1f 00 00 74 c6 85 50 1f 00 00 72 c6 85 51 1f 00 00 69 c6 85 52 1f 00 00 56}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CER_2147843582_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CER"
        threat_id = "2147843582"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "wsc_UUIDS.dll" ascii //weight: 1
        $x_1_2 = "D:\\project\\doge-cloud\\targetfiles" ascii //weight: 1
        $x_1_3 = "on_avast_dll_unload" ascii //weight: 1
        $x_1_4 = {0f 1f 44 00 00 83 f9 0a 0f 4c c2 3d ?? ?? ?? ?? 7e ?? 3d ?? ?? ?? ?? 0f ?? ?? ?? ?? ?? 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_UTI_2147843603_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.UTI!MTB"
        threat_id = "2147843603"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 8b 87 08 01 00 00 33 c9 44 2b 47 18 8b 57 10 41 81 e8 ff 55 00 00 44 8d 49 40 ff 15 39 49 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {0f af c2 41 8b d0 89 43 64 2b 83 e8 00 00 00 89 43 64 48 8b 83 90 00 00 00 c1 ea 08 88 14 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_UP_2147843663_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.UP!MTB"
        threat_id = "2147843663"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 d0 44 0f af 43 44 0f af d0 48 8b 83 a8 00 00 00 89 93 98 00 00 00 41 8b d0 c1 ea 10 88 14 01 b8 24 fa 14 00 2b 43 58 41 8b d0}  //weight: 1, accuracy: High
        $x_1_2 = {41 8b 81 8c 00 00 00 41 29 81 e4 00 00 00 41 8b 41 68 49 8b 89 b8 00 00 00 31 04 11}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_SS_2147843986_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.SS!MTB"
        threat_id = "2147843986"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 8b 4c 24 04 41 30 c9 4d 63 e4 48 8b 44 24 20 46 88 0c 20 41 8d 54 24 01 83 fa 0c 49 be 90 c6 14 96 7a 78 29 cf 4d 0f 44 f7 49 8d 80 51 d1 2e 0a 31 ff 49 39 c6 40 0f 92 c7 c1 e7 03 8d 04 7f 4a 8b 44 18 70}  //weight: 1, accuracy: High
        $x_1_2 = "NimDestroyGlobals" ascii //weight: 1
        $x_1_3 = "NimMain" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_KP_2147844424_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.KP!MTB"
        threat_id = "2147844424"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {42 88 1c 30 4b 8d 0c 37 48 ff c1 49 ff c6 4c 89 74 24 ?? 4c 39 e1 74}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 e9 48 ff c5 48 39 fd 48 0f 43 ee 43 0f b6 1c 37 41 32 5c 0d ?? 4c 3b 74 24 ?? 75 ca}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_CobaltStrike_ASJ_2147845011_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.ASJ!MTB"
        threat_id = "2147845011"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4c 8b 54 24 38 99 41 f7 f8 48 63 d2 0f b6 04 16 41 32 04 09 41 88 04 0a 48 8b 35 6f 1b 00 00 0f b6 04 16 41 88 04 09 48 83 c1 01 39 0d 65 1b 00 00 77 cb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_ASJ_2147845011_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.ASJ!MTB"
        threat_id = "2147845011"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {48 89 df 48 89 ce 48 8b 5c 24 ?? 48 89 c1 48 8b 44 24 ?? e8 ?? ?? ?? ?? 48 89 44 24 48 48 89 5c 24 58 48 8b 4c 24 38 48 8d ?? ?? ?? ?? 00 48 89 cb e8 ?? ?? ?? ?? 48 89 44 24}  //weight: 4, accuracy: Low
        $x_1_2 = "main.AesDecrypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_ZD_2147845126_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.ZD!MTB"
        threat_id = "2147845126"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 0f b7 12 49 81 cb ?? ?? ?? ?? 49 81 eb ?? ?? ?? ?? 49 21 d5 48 01 ea 4c 21 e3 24 ?? 49 c7 c2 ?? ?? ?? ?? 49 81 c5 ?? ?? ?? ?? 49 29 d5 48 89 ef 48 81 c7 ?? ?? ?? ?? 49 31 cb 4c 31 d1 4c 01 e9 49 81 c3 ?? ?? ?? ?? 8a 1f 4c 09 e9 4d 01 d5 80 f3 a0 4d 21 ea 49 81 ea ?? ?? ?? ?? 49 31 dd 49 81 f3 ?? ?? ?? ?? 80 eb ?? 80 fb 00 0f 85}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_LKS_2147845135_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.LKS!MTB"
        threat_id = "2147845135"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 32 10 88 11 41 32 10 41 88 10 32 11 88 11 eb}  //weight: 1, accuracy: High
        $x_1_2 = {41 0f b6 54 0d 00 41 8a 0c 0e 88 0c 17 48 63 c8 ff c0 48 39 f1 72 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_CobaltStrike_SK_2147845297_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.SK!MTB"
        threat_id = "2147845297"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 d8 48 89 d9 48 c1 f8 ?? 48 c1 f9 ?? 31 d8 31 c8 48 89 d9 48 c1 f9 ?? 31 c8 30 44 1a ?? 48 ?? ?? ?? 4c 39 c3 75}  //weight: 1, accuracy: Low
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_LKV_2147845334_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.LKV!MTB"
        threat_id = "2147845334"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 00 32 00 34 00 2e 00 37 00 30 00 2e 00 31 00 38 00 39 00 2e 00 38 00 38 00 3a 00 38 00 30 00 38 00 30 00 2f 00 [0-15] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = {70 65 6c 6f 61 64 65 72 5c 70 65 6c 6f 61 64 65 72 5f 36 34 5c [0-15] 5c 52 65 6c 65 61 73 65 5c 70 65 6c 6f 61 64 65 72 [0-15] 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_ZB_2147845601_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.ZB!MTB"
        threat_id = "2147845601"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 98 33 d2 b9 3e 00 00 00 48 f7 f1 48 8b c2 89 44 24 24 48 63 44 24 24}  //weight: 1, accuracy: High
        $x_1_2 = {8b 44 24 28 ff c0 89 44 24 28 48 8b 44 24 30 8b 00 48 8b 4c 24 30 48 03 c8 48 8b c1 48 89 44 24 30 48 8b 44 24 30 83 38 00 75 99 41 b8 00 80 00 00 33 d2 48 8b 4c 24 30}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_ZB_2147845601_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.ZB!MTB"
        threat_id = "2147845601"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {43 30 14 08 48 8b ca 48 8b c2 48 c1 e9 38 48 83 c9 01 48 c1 e0 08 48 8b d1 49 ff c0 48 33 d0 49 83 f8 ?? 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_GZ_2147845648_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.GZ!MTB"
        threat_id = "2147845648"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bridipivmsnsupus" ascii //weight: 1
        $x_1_2 = "GOMAXPROCS" ascii //weight: 1
        $x_1_3 = "OTTOttcfwOFFwOF2PK" ascii //weight: 1
        $x_1_4 = " Go buildinf:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_GZ_2147845648_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.GZ!MTB"
        threat_id = "2147845648"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 f7 e8 41 03 d0 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 0f be c2 6b c8 ?? 41 8a c0 41 ff c0 2a c1 04 ?? 41 30 01 49 ff c1 41 83 f8}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c3 41 f7 e8 41 03 d0 c1 fa 05 8b c2 c1 e8 1f 03 d0 0f be c2 6b c8 ?? 41 8a c0 2a c1 04 ?? 41 30 01 44 03 c7 4c 03 cf 41 83 f8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_VCX_2147845829_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.VCX!MTB"
        threat_id = "2147845829"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {44 89 c0 41 f7 e9 44 89 c0 c1 f8 ?? c1 fa ?? 29 c2 b8 ?? ?? ?? ?? 0f af d0 44 89 c0 29 d0 48 8b 54 24 70 48 98 41 0f b6 04 02 32 04 0a 48 8b 54 24 ?? 88 04 0a 49 8d 48 ?? 48 39 4c 24 ?? 77}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_B_2147845868_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.B!MTB"
        threat_id = "2147845868"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {41 f7 ea 44 89 c8 c1 f8 1f 44 01 ca c1 fa ?? 29 c2 b8 ?? ?? ?? ?? 0f af d0 29 d1 48 63 c9 0f b6 04 0f 43 32 04 0b 42 88 04 06 4d 8d 41}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_PBE_2147846048_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.PBE!MTB"
        threat_id = "2147846048"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 63 8c 24 ?? ?? ?? ?? 48 8b 84 24 ?? ?? ?? ?? 44 0f b6 04 08 8b 84 24 ?? ?? ?? ?? 99 b9 27 00 00 00 f7 f9 48 63 ca 48 8b 84 24 ?? ?? ?? ?? 0f b6 04 08 41 8b d0 33 d0 48 63 8c 24 ?? ?? ?? ?? 48 8b 84 24 ?? ?? ?? ?? 88 14 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_WI_2147846408_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.WI!MTB"
        threat_id = "2147846408"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b8 00 04 00 00 48 6b c0 04 48 8d 0d fc 68 01 00 48 03 c8 48 8b c1 8b 0c 24 c1 e9 18 48 8b 54 24 28 0f b6 12 33 ca 8b c9 8b 14 24 c1 e2 08 8b 04 88 33 c2 89 04 24 48 8b 44 24 28 48 ff c0 48 89 44 24 28 48 8b 44 24 30 48 ff c8 48 89 44 24 30 48 83 7c 24 30 00 75 a8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_WI_2147846408_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.WI!MTB"
        threat_id = "2147846408"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 1c 24 48 8d 64 24 ?? c6 83 ?? ?? ?? ?? ?? 1d ?? ?? ?? ?? 15 ?? ?? ?? ?? e0 ?? d0 0b c0 09 ?? 08 60 ?? 30 06 50 a0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_ZC_2147846492_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.ZC!MTB"
        threat_id = "2147846492"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 85 db 0f 84 ?? ?? ?? ?? 41 50 41 54 49 c7 c4 00 00 00 00 4d 89 e0 41 5c 49 01 c0 41 54 49 c7 c4 00 00 00 00 4d 01 c4 49 01 0c 24 41 5c ff 34 24 41 58 48 81 c4 ?? ?? ?? ?? 48 83 c0 ?? 83 eb 01 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_ZC_2147846492_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.ZC!MTB"
        threat_id = "2147846492"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 c8 89 8c 24 ?? ?? ?? ?? 8a 54 34 ?? 0f b6 44 0c ?? 88 44 34 ?? 88 54 0c ?? 8b 94 24 ?? ?? ?? ?? 8b b4 24 ?? ?? ?? ?? 0f b6 4c 14 ?? 0f b6 44 34 ?? 03 c8 0f b6 c1 8b 4c 24 ?? 0f b6 44 04 ?? 30 04 19 41 89 4c 24 ?? 3b cf 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_SPS_2147846732_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.SPS!MTB"
        threat_id = "2147846732"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 c7 45 68 ?? ?? ?? ?? 8b 45 24 41 b9 ?? ?? ?? ?? 41 b8 ?? ?? ?? ?? 8b d0 33 c9 ff 15 ?? ?? ?? ?? 48 89 45 68 48 83 7d 68 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_ME_2147846809_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.ME!MTB"
        threat_id = "2147846809"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 33 1c 87 45 89 e0 41 c1 ec 08 45 0f b6 e4 47 0f b6 24 23 4c 8d 3d 29 99 0e 00 43 33 1c a7 45 0f b6 c0 47 0f b6 04 18 4c 8d 25 15 9d 0e 00 43 33 1c 84}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_ME_2147846809_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.ME!MTB"
        threat_id = "2147846809"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {f0 00 23 00 0b 02 0e 1d 00 bc 08 00 00 ?? 66}  //weight: 5, accuracy: Low
        $x_2_2 = {e3 68 ee be b8 2f bf b7 47 54 57 91 d1 a3 6c 7c 22 09 44 c7 3c cc 31 54 67 78 87 60 ab 43 39 7c 36 5f 22 ca 94 02 59 31 77 b1 b7 53 8c d6 f3 cd}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_ME_2147846809_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.ME!MTB"
        threat_id = "2147846809"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 33 c4 48 89 44 24 38 33 c9 48 8d 44 24 30 48 89 44 24 28 4c 8d 05 ?? ?? ?? ?? 45 33 c9 89 4c 24 20 33 d2 89 4c 24 30 ff 15}  //weight: 5, accuracy: Low
        $x_5_2 = {8b 7c 24 48 33 c9 8b d7 41 b8 00 30 00 00 44 8b ff 44 8d 49 04 ff 15}  //weight: 5, accuracy: High
        $x_5_3 = "StartDllLoadData" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_MF_2147846885_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MF!MTB"
        threat_id = "2147846885"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {35 fd 00 00 00 88 05 ab 54 00 00 0f b6 05 a4 54 00 00 83 e0 6e 88 05 9b 54 00 00 0f b6 05 94 54 00 00 83 c8 43 88 05 8b 54 00 00 0f b6 05 84 54 00 00 2d 82 a3 09 53 89 05 75 54 00 00 0f b6 05 72 54 00 00 0d ca da ac 51}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_MF_2147846885_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MF!MTB"
        threat_id = "2147846885"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 8b 83 e8 00 00 00 45 8b 04 01 49 83 c1 04 8b 83 8c 00 00 00 33 83 d0 00 00 00 44 0f af 05 ?? ?? ?? ?? 83 e8 04 31 05 ?? ?? ?? ?? 8b 43 60 09 05 ?? ?? ?? ?? 8b 83 f0 00 00 00 2b 05 ?? ?? ?? ?? 41 8b d0 01 83 c0 00 00 00 48 8b 05 ?? ?? ?? ?? c1 ea 08 48 63 88 94 00 00 00 48 8b 80 08 01 00 00 88 14 01}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_RST_2147846891_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.RST!MTB"
        threat_id = "2147846891"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff c2 0f b6 d2 0f b6 9c 14 80 01 00 00 40 00 de 40 02 b4 14 80 00 00 00 40 0f b6 ee 0f b6 84 2c 80 01 00 00 88 84 14 80 01 00 00 88 9c 2c 80 01 00 00 02 9c 14 80 01 00 00 0f b6 c3 0f b6 84 04 80 01 00 00 41 30 04 3c 48 ff c7 49 39 fd 75 b0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CRIO_2147846997_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CRIO!MTB"
        threat_id = "2147846997"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f4 3b 45 e4 7d 4a 4c 8b 45 f8 8b 45 f4 48 98 48 8d 14 c5 00 00 00 00 48 8d ?? ?? ?? ?? ?? 48 01 c2 8b 45 f4 48 98 48 8d 0c c5 00 00 00 00 48 8d ?? ?? ?? ?? ?? 48 8b 04 01 48 89 c1 48 8b 05 3c 6c 0f 00 ff d0 48 83 45 f8 06 83 45 f4 01 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CRIY_2147847096_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CRIY!MTB"
        threat_id = "2147847096"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 c2 83 e2 ?? 41 8a 14 14 32 54 05 00 88 14 03 48 ff c0 39 c6 7f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_MJ_2147847146_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MJ!MTB"
        threat_id = "2147847146"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f af d0 48 8b 83 c8 00 00 00 88 14 01 44 8b 83 b4 00 00 00 8b 4b 54 44 8b 8b e0 00 00 00 8b ab d8 00 00 00 8b c5 ff 83 88 00 00 00 41 8d ?? ?? ?? ?? ?? 8b 73 58 41 33 c0}  //weight: 5, accuracy: Low
        $x_5_2 = {89 43 54 89 0b 8d 82 ?? ?? ?? ?? 41 03 c1 01 43 08 44 8b 73 08 49 81 fb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_MJ_2147847146_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MJ!MTB"
        threat_id = "2147847146"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0f a2 44 8b c9 c7 05 00 91 05 00 01 00 00 00 81 f1 63 41 4d 44 44 8b d2 81 f2 65 6e 74 69 8b fb 81 f7 41 75 74 68 8b f0 0b fa 44 8b c3 0b f9 41 81 f0 47 65 6e 75 33 c9 41 81 f2 69 6e 65 49 45 0b d0 b8 01 00 00 00 44 8b 05 49 b4 05 00 41 81 f1 6e 74 65 6c 45 0b d1}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_MG_2147847247_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MG!MTB"
        threat_id = "2147847247"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 89 c1 48 31 d2 49 89 d8 4d 31 c9 52 68 00 02 40 84 52 52 41 ba eb 55 2e 3b ff d5 48 89 c6 48 83 c3 50 6a 0a 5f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_MH_2147847248_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MH!MTB"
        threat_id = "2147847248"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 89 84 24 88 00 00 00 48 8b 8c 24 b8 00 00 00 89 ca bb cd cc cc cc 48 0f af da 48 c1 eb 22 48 89 5c 24 60 48 8b 94 24 b0 00 00 00 31 f6 31 ff 45 31 c0 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_MH_2147847248_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MH!MTB"
        threat_id = "2147847248"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {0f b6 d1 4d 8d 40 01 33 c2 8b c8 d1 e8 83 e1 01 f7 d9 81 e1 20 83 78 ed 33 c8 8b c1 d1 e9 83 e0 01 f7 d8 25 20 83 78 ed 33 c1 8b c8 d1 e8}  //weight: 5, accuracy: High
        $x_5_2 = "AtomLdr.dll" ascii //weight: 5
        $x_5_3 = "InitializeAtomSystem" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_MH_2147847248_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MH!MTB"
        threat_id = "2147847248"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ACEENMJKRWTBXdwrWlqVnPTWQ" ascii //weight: 1
        $x_1_2 = "ADPlbZDZlbjrOtxfUvqD" ascii //weight: 1
        $x_1_3 = "ANICoAGKEuagFlWTf" ascii //weight: 1
        $x_1_4 = "AdpKkTEKERtxIlTVHnbowzaBf" ascii //weight: 1
        $x_1_5 = "AoEMMOwxOEO" ascii //weight: 1
        $x_1_6 = "AsMjpmzbwtUu" ascii //weight: 1
        $x_1_7 = "AunOOfXInZqitqQwUSfp" ascii //weight: 1
        $x_1_8 = "AziSRPfWBfkZRpo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CAT_2147847551_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CAT!MTB"
        threat_id = "2147847551"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 95 10 01 00 00 48 8d 8d b0 00 00 00 e8 ?? ?? ?? ?? 48 8b 8d 38 03 00 00 ff d0 90 48 8d 8d b0 00 00 00 e8 ?? ?? ?? ?? 48 8b 95 50 01 00 00 48 8d 8d b0 00 00 00 e8 ?? ?? ?? ?? ff d0 8b d8 48 8b 95 58 01 00 00 48 8d 8d b0 00 00 00 e8 ?? ?? ?? ?? b9 e8 03 00 00 ff d0 48 8b 95 50 01 00 00 48 8d 8d b0 00 00 00 e8 ?? ?? ?? ?? ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CO_2147847559_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CO!MTB"
        threat_id = "2147847559"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 14 08 f7 d2 88 14 08 48 ff c1 48 39 cb 7f ef}  //weight: 1, accuracy: High
        $x_1_2 = "A7d8Gw8XN////76uvq+trqm3zi2at3Stn7d0ree3dK3ft3SNr7fwSLW1ss42t84/U" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CREE_2147847567_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CREE!MTB"
        threat_id = "2147847567"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 00 41 8b c9 c1 c9 ?? 41 ff c3 03 c8 41 8b c3 49 03 c2 44 33 c9 80 38 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 4c 24 08 48 89 54 24 10 4c 89 44 24 18 4c 89 4c 24 20 48 83 ec ?? 8b 0d 81 32 0b 00 e8 ?? ?? ?? ?? 48 83 c4 ?? 48 8b 4c 24 08 48 8b 54 24 10 4c 8b 44 24 18 4c 8b 4c 24 20 4c 8b d1 0f 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_F_2147847668_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.F!MTB"
        threat_id = "2147847668"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 89 c2 83 e2 ?? 41 8a 14 14 32 54 05 ?? 88 14 03 48 ff c0 eb}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_SDN_2147847980_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.SDN!MTB"
        threat_id = "2147847980"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ce b8 e1 83 0f 3e f7 ee ff c6 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 6b c2 ?? 2b c8 48 63 c1 48 8d 0d ?? ?? ?? ?? 8a 04 08 43 32 04 01 41 88 00 49 ff c0 3b f7 72}  //weight: 1, accuracy: Low
        $x_1_2 = "StartUp" ascii //weight: 1
        $x_1_3 = "FindNextVolumeMountPointW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_KVM_2147848247_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.KVM!MTB"
        threat_id = "2147848247"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 33 c0 4c 8d 4c 24 ?? b8 f7 12 da 4b 41 f7 e8 c1 fa 04 8b c2 c1 e8 1f 03 d0 0f be c2 6b c8 36 41 8a c0 41 ff c0 2a c1 04 37 41 30 01 49 ff c1 41 83 f8 ?? 7c d2 4c 8d 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_WAR_2147848361_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.WAR!MTB"
        threat_id = "2147848361"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 f7 e8 c1 fa 04 8b c2 c1 e8 ?? 03 d0 41 8b c0 41 ff c0 8d 0c 92 c1 e1 ?? 2b c1 48 63 c8 48 8b 44 24 ?? 42 8a 8c 11 ?? ?? ?? ?? 43 32 8c 11 ?? ?? ?? ?? 41 88 0c 01 49 63 c0 49 ff c1 48 3b 44 24 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CRHX_2147848472_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CRHX!MTB"
        threat_id = "2147848472"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fc48:83e4:f0e8:c800:0:4151:4150:5251" ascii //weight: 1
        $x_1_2 = "5648:31d2:6548:8b52:6048:8b52:1848:8b52" ascii //weight: 1
        $x_1_3 = "2048:8b72:5048:fb7:4a4a:4d31:c948:31c0" ascii //weight: 1
        $x_1_4 = "ac3c:617c:22c:2041:c1c9:d41:1c1:e2ed" ascii //weight: 1
        $x_1_5 = "5241:5148:8b52:208b:423c:4801:d066:8178" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CRUN_2147848642_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CRUN!MTB"
        threat_id = "2147848642"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 83 f1 59 45 88 4c 18 ff 48 ff c0 4c 89 c1 48 3d 9e 03 00 00 7d ?? 4c 8d 41 01 44 0f b6 4c 04 62 66 90 4c 39 c2 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_BX_2147848670_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.BX!MTB"
        threat_id = "2147848670"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 63 d0 48 8b 45 20 48 01 d0 0f b6 08 48 8b 55 e0 8b 45 fc 48 98 0f b6 04 02 31 c8 88 45 df 8b 45 fc 48 63 d0 48 8b 45 20 48 01 c2 0f b6 45 df 88 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_BX_2147848670_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.BX!MTB"
        threat_id = "2147848670"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 88 4c 24 ?? 48 ?? ?? ?? 0f 84 ?? ?? ?? ?? 89 c1 c1 e9 ?? 41 32 48 ?? 41 ?? ?? ?? ?? 48 83 fe ?? 0f 84 ?? ?? ?? ?? 89 c1 c1 e9 ?? 41 32 48 ?? 41 88 4c 24 ?? 48 83 fe ?? 0f 84 ?? ?? ?? ?? c1 e8 ?? 41 32 40 ?? 41}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_BY_2147848671_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.BY!MTB"
        threat_id = "2147848671"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c2 89 d0 c1 e0 ?? 01 d0 01 c0 29 c1 89 ca 48 63 c2 48 ?? ?? ?? ?? ?? ?? 0f b6 14 10 8b 85 ?? ?? ?? ?? 48 63 c8 48 ?? ?? ?? ?? ?? ?? 48 01 c8 44 31 c2 88 10 83 85 ?? ?? ?? ?? ?? 8b 45 ?? 39 85 ?? ?? ?? ?? 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_ZG_2147848731_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.ZG!MTB"
        threat_id = "2147848731"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 f7 e9 41 8b c9 41 ff c1 c1 fa 03 8b c2 c1 e8 1f 03 d0 6b c2 11 2b c8 48 63 c1 0f b6 4c 04 30 41 30 4a ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_BNK_2147848825_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.BNK!MTB"
        threat_id = "2147848825"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {65 48 8b 04 25 60 00 00 00 48 89 bc 24 80 00 00 00 48 8b 48 18 4c 8b 59 20 4d 85 db}  //weight: 1, accuracy: High
        $x_1_2 = "ServiceMain" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_ZP_2147848913_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.ZP!MTB"
        threat_id = "2147848913"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 4c 24 40 48 89 08 48 8b 54 24 58 48 89 50 08 48 8b 54 24 48 48 89 50 10}  //weight: 1, accuracy: High
        $x_1_2 = "48ffcd555d48ffc5" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_BZ_2147848951_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.BZ!MTB"
        threat_id = "2147848951"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 01 d0 0f b6 08 8b 45 ?? 48 63 d0 48 8b 45 ?? 48 01 d0 0f b6 10 8b 45 ?? 4c 63 c0 48 8b 45 ?? 4c 01 c0 31 ca 88 10 83 45 ?? ?? 83 45 ?? ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_ML_2147849058_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.ML!MTB"
        threat_id = "2147849058"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 8b 04 02 49 83 c2 04 48 8b 05 ?? ?? ?? ?? 45 0f af 81 8c 00 00 00 8b 88 60 01 00 00 81 c1 ?? ?? ?? ?? 41 03 89 f8 00 00 00 41 8b d0 41 31 49 34 8b 05 ?? ?? ?? ?? 35 62 93 11 00 c1 ea 10 41 01 81 94 00 00 00 48 8b 05 ?? ?? ?? ?? 48 63 88 a4 00 00 00 49 8b 81 e0 00 00 00 88 14 01}  //weight: 1, accuracy: Low
        $x_1_2 = "CPHylI2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CRIT_2147849059_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CRIT!MTB"
        threat_id = "2147849059"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SV5FVlFMjeFMhegkBAQETIkZ7vv7+0yN20yFx6BqBQT710W89LGmUmwABAQEXkyN" ascii //weight: 1
        $x_1_2 = "fvUBAQEBAQEBAQEFAUEBAobvgoEsA3JJbwFSMklUGxtdyR0dmtjdmVpJGdlamprcC" ascii //weight: 1
        $x_1_3 = "RmYSR2cWokbWokQEtXJGlrYGEqCQkOIAQEBAQEBASA2mrbxLsEiMS7BIjEuwSIolX" ascii //weight: 1
        $x_1_4 = "KiMW7BIjnVNaIXLsEiFobw4jFuwSINX3LiO27BIg1fcqITbsEiDV9yYjOuwSIzcOX" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_ZE_2147849066_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.ZE!MTB"
        threat_id = "2147849066"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 c1 08 da 44 20 c3 08 cb 89 d9 30 c1 20 d9 44 08 c0 89 d3 30 c3 08 d0 34 01 08 d8 89 cb 80 f3 01 89 c2 80 f2 01 20 d8 08 d3 20 ca 08 c2 89 d9 30 d1 be ?? ?? ?? ?? b8 ?? ?? ?? ?? f6 c1 01 75 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_ZE_2147849066_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.ZE!MTB"
        threat_id = "2147849066"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {49 2b c1 48 0f af c6 48 03 c8 48 0f af ff 48 8d 04 7f 48 2b c8 49 03 cd 42 0f b6 94 32 ?? ?? ?? ?? 42 32 94 31 ?? ?? ?? ?? 48 8d 04 76 49 8b cd 48 2b c8 48 8b 84 24 ?? ?? ?? ?? 88 14 01 41 ff c4 49 ff c5 49 63 c4 48 3b 84 24 ?? ?? ?? ?? 73}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_LD_2147849127_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.LD!MTB"
        threat_id = "2147849127"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 0f b6 54 3b ?? 8d 42 ?? 8b cb 3c ?? b8 ?? ?? ?? ?? 0f 46 c8 0a d1 0f be c2 49 33 c2 0f b6 c8 41 c1 ea ?? 48 8d 05 ?? ?? ?? ?? 44 33 14 88 41 f7 d2 41 81 fa ?? ?? ?? ?? 0f 84 ?? ?? ?? ?? ff c6 41 3b f4 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_LKAC_2147849543_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.LKAC!MTB"
        threat_id = "2147849543"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {29 81 6c 01 00 00 b8 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? 41 01 41 64 48 63 0d ?? ?? ?? ?? 49 8b 81 18 01 00 00 44 88 04 01 ff 05 ?? ?? ?? ?? 49 81 fa 00 dd 01 00 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_MM_2147849572_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MM!MTB"
        threat_id = "2147849572"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "\\SudSolver.pdb" ascii //weight: 5
        $x_1_2 = "Capture device info" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_MM_2147849572_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MM!MTB"
        threat_id = "2147849572"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {f0 00 23 00 0b 02 0e 1d 00 c0 08 00 00 c0 97}  //weight: 5, accuracy: High
        $x_2_2 = {ff 74 24 30 9d 48 8d 64 24 58 e8 53 92 7d 02 96 64 87 bd 01 9e e0 19 d8 81 e7 2b 86 03 eb 3c ad e1 f3 38 4f 6a 37 04 d7 b8 59 f4 bd 22 3c 71 40}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_MN_2147849679_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MN!MTB"
        threat_id = "2147849679"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4c 89 c1 ba 01 00 00 00 81 e1 ff 01 00 00 49 89 c8 48 d3 e2 49 c1 f8 06 4a 85 54 c0 10 0f 95 c2 88 d0 48 83 c4 28}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_MN_2147849679_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MN!MTB"
        threat_id = "2147849679"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 63 c8 48 8b 84 24 [0-4] 44 0f b6 04 08 48 63 84 24 [0-4] 33 d2 b9 ?? ?? ?? ?? 48 f7 f1 0f b6 44 14 70 41 8b d0 33 d0}  //weight: 2, accuracy: Low
        $x_2_2 = {03 c1 2b 44 24 58 03 84 24 ?? ?? ?? ?? 03 84 24 ?? ?? ?? ?? 03 84 24 ?? ?? ?? ?? 03 84 24 ?? ?? ?? ?? 2b 84 24 [0-4] 48 63 c8 48 8b 84 24 [0-4] 88 14 08}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_AWR_2147849701_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.AWR!MTB"
        threat_id = "2147849701"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 48 c1 e9 ?? 33 45 8f 33 cf 89 4c 24 2c 66 48 0f 7e c9 89 44 24 28 8b c1 0f 10 44 24 20 48 c1 e9 20 41 33 c7 33 ce 89 44 24 50 89 4c 24 54 66 0f 73 d9 08 66 48 0f 7e c9 8b c1 48 c1 e9 20 41 33 ce 41 33 c4 48 83 6d 67}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CRTJ_2147849829_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CRTJ!MTB"
        threat_id = "2147849829"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 7c 24 20 41 b9 40 00 00 00 8b d7 41 b8 00 30 00 00 33 c9 ff d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_BT_2147850083_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.BT!MTB"
        threat_id = "2147850083"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {41 0f b6 04 00 88 04 0a c7 84 24 [0-4] 01 00 00 00 b8 01 00 00 00 48 6b c0 00 c6 84 04 [0-4] 65 b8 01 00 00 00 48 6b c0 01 c6 84 04 [0-4] 72 b8 01 00 00 00 48 6b c0 02 c6 84 04 [0-4] 72 b8 01 00 00 00 48 6b c0 03 48 89 84 24 [0-4] 48 83 bc 24 [0-4] 0a 73}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_MQ_2147850095_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MQ!MTB"
        threat_id = "2147850095"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {b8 ed 73 48 4d 41 f7 e8 c1 fa 04 8b c2 c1 e8 1f 03 d0 0f be c2 6b c8 ?? 41 8a c0 41 ff c0 2a c1 04 ?? 41 30 01 49 ff c1 41 83 f8 16 7c d2}  //weight: 6, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_HLO_2147850220_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.HLO!MTB"
        threat_id = "2147850220"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 f7 e8 41 03 d0 c1 fa 05 8b c2 c1 e8 1f 03 d0 6b d2 2e 41 8b c0 2b c2 48 63 c8 42 ?? ?? ?? ?? ?? ?? ?? ?? 43 32 94 11 ?? ?? ?? ?? 48 8b 44 24 30 41 88 14 01 41 ff c0 49 ff c1 49 63 c0 48 3b 44 24 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_AM_2147850506_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.AM!MTB"
        threat_id = "2147850506"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 63 45 e4 48 3b 45 f0 0f 83 ?? ?? ?? ?? 48 8d 05 ?? ?? ?? ?? b9 ?? ?? ?? ?? 48 8d 15 ?? ?? ?? ?? 4c 63 45 e4 46 0f b6 0c 02 44 8b 55 e4 48 89 45 b8 44 89 d0 99}  //weight: 1, accuracy: Low
        $x_1_2 = {f7 f9 4c 63 c2 4c 8b 5d b8 43 0f be 0c 03 41 31 c9 44 88 cb 4c 8b 45 e8 48 63 75 e4 41 88 1c 30 8b 45 e4 83 c0 01 89 45 e4 e9 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_MR_2147850597_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MR!MTB"
        threat_id = "2147850597"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {f0 00 23 00 0b 02 0e 1d 00 c0 08 00 00 c0 97 01 00 00 00 00 50 c8 eb 04 00 10}  //weight: 5, accuracy: High
        $x_5_2 = {f0 00 23 00 0b 02 0e 1d 00 bc 08 00 00 86 66 00 00 00 00 00 1b 23 7d 02 00 10}  //weight: 5, accuracy: High
        $x_5_3 = {f0 00 23 00 0b 02 0e 1d 00 c6 08 00 00 ce eb 01 00 00 00 00 b8 eb 8d 05 00 10}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_CobaltStrike_MS_2147850599_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MS!MTB"
        threat_id = "2147850599"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {f0 00 23 00 0b 02 0e 1d 00 ba 08 00 00 14 7f 00 00 00 00 00 33 2f 56 02 00 10}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_LKAE_2147850743_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.LKAE!MTB"
        threat_id = "2147850743"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f3 0f 7f 04 30 41 8d 40 10 41 83 c0 ?? f3 0f 6f 04 30 66 0f fc c8 66 0f ef cb f3 0f 7f 0c 30 3b da 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_LKAF_2147850744_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.LKAF!MTB"
        threat_id = "2147850744"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 02 48 8d 52 01 04 ?? 34 ?? 88 42 ff 48 83 ef 01 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_LKAG_2147850745_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.LKAG!MTB"
        threat_id = "2147850745"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 f0 21 f8 31 f7 09 c7 89 7c 24 44 44 89 c0 e9 9f fe ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_AMX_2147850769_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.AMX!MTB"
        threat_id = "2147850769"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f be 04 08 41 8b d0 33 d0}  //weight: 1, accuracy: High
        $x_1_2 = {2b c1 48 63 c8 48 8b 44 24 30 88 14 08 e9 8a fd ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_AMX_2147850769_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.AMX!MTB"
        threat_id = "2147850769"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {41 f7 e8 41 03 d0 c1 fa 09 8b ca c1 e9 1f 03 d1 69 ca 7b 03 00 00 44 2b c1 41 fe c0 45 32 04 3f 45 32 c6 44 88 07 48 8d 7f 01 48 83 ee 01 75 c2}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CRDD_2147850804_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CRDD!MTB"
        threat_id = "2147850804"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ba 00 00 08 00 33 c9 41 b9 40 00 00 00 41 b8 00 10 00 00 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CRDS_2147850807_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CRDS!MTB"
        threat_id = "2147850807"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c9 ba e0 93 04 00 41 b8 00 10 00 00 44 8d 49 40 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CRDP_2147850808_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CRDP!MTB"
        threat_id = "2147850808"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "jsporvjlfsqmlsamxdrvitxha" ascii //weight: 1
        $x_1_2 = "qeebviaksevjtw" ascii //weight: 1
        $x_1_3 = "eepftqjfhuduethzuojwprtkpc" ascii //weight: 1
        $x_1_4 = "sjxfwnsopufqqjyyjnkt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CRDV_2147850810_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CRDV!MTB"
        threat_id = "2147850810"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 b9 40 00 00 00 48 63 d8 41 b8 00 10 00 00 48 8b d3 33 c9 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CRDZ_2147850820_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CRDZ!MTB"
        threat_id = "2147850820"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 0b 48 8b d7 ff 15 ?? ?? ?? ?? 85 c0 75 ?? 48 83 c7 10 48 83 c3 08 48 3b dd 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CBVC_2147850821_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CBVC!MTB"
        threat_id = "2147850821"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4a 8d 14 07 49 ff c0 0f b6 04 13 f6 d0 88 02 49 81 f8}  //weight: 1, accuracy: High
        $x_1_2 = {80 34 39 bb 48 ff c1 48 81 f9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_LKAH_2147851154_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.LKAH!MTB"
        threat_id = "2147851154"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 b9 40 00 00 00 41 b8 00 10 00 00 49 ?? ?? 33 ?? ff}  //weight: 1, accuracy: Low
        $x_1_2 = {48 83 ec 28 b9 6b cc b4 a7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_LKAJ_2147851164_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.LKAJ!MTB"
        threat_id = "2147851164"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b7 c0 89 f1 c1 e1 05 01 ce 01 c6 0f b7 02 48 83 c2 02 66 85 c0 75 e8 81 fe 36 af 17 51}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_MI_2147851180_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MI!MTB"
        threat_id = "2147851180"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Projects\\evasionC_go\\workingSpace" ascii //weight: 1
        $x_1_2 = "_seh_filter_dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_MI_2147851180_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MI!MTB"
        threat_id = "2147851180"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BdplTlKPlIwJjXZVredJNvIJez" ascii //weight: 1
        $x_1_2 = "BiymJZqVmlYB" ascii //weight: 1
        $x_1_3 = "BoevVBacejSmwcZ" ascii //weight: 1
        $x_1_4 = "DGivSvXuIrBHNDCUPz" ascii //weight: 1
        $x_1_5 = "DZaFRSZ" ascii //weight: 1
        $x_1_6 = "DkKbDRXEPYKgIX" ascii //weight: 1
        $x_1_7 = "DmVstJBIfuoAcx" ascii //weight: 1
        $x_1_8 = "FlHBLeHpTIlLBOtEqu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_JUL_2147851218_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.JUL!MTB"
        threat_id = "2147851218"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c8 48 8b 05 72 db 04 00 31 0d 2c db 04 00 31 14 03 48 83 c3 04 8b 15 3b db 04 00 8b 0d bd db 04 00 2b 0d db da 04 00 8b 05 ?? ?? ?? ?? 83 c0 d4 03 c8 8b 05 ?? ?? ?? ?? 89 0d 64 db 04 00 05}  //weight: 1, accuracy: Low
        $x_1_2 = {8b ca 2b 0d 03 db 04 00 03 c8 8b 05 ?? ?? ?? ?? 89 0d c5 da 04 00 8d 8a 66 17 fa ff 01 0d 8d da 04 00 48 8b 0d 6e da 04 00 2b 81 ec 00 00 00 35 f1 95 e4 ff 29 81 d4 00 00 00 8b 0d 93 da 04 00 48 8b 15 50 da 04 00 81 c1 2b 24 fd ff 03 0d 1c db 04 00 01 4a 08 8b 15 8b da 04 00 03 15 dd da 04 00 89 15 ?? ?? ?? ?? 48 81 fb 80 03 00 00 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_JID_2147851228_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.JID!MTB"
        threat_id = "2147851228"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f af c2 01 c1 8b 15 13 a5 06 00 8b 05 01 a5 06 00 0f af c2 29 c1 8b 15 fe a4 06 00 8b 05 ?? ?? ?? ?? 0f af c2 29 c1 89 c8 48 63 d0 48 8d 05 ?? ?? ?? ?? 0f b6 04 02 44 31 c8 41 88 00 83 45 fc 01 8b 45 fc 48 63 d0 48 8b 45 e8 48 39 c2 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CH_2147851264_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CH!MTB"
        threat_id = "2147851264"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {89 ea 29 ca 48 63 ca 0f b6 0c 0e 32 0c 03 41 88 0c 06 b8}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CH_2147851264_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CH!MTB"
        threat_id = "2147851264"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 ed c1 fa ?? 8b c2 c1 e8 ?? 03 d0 8b c5 ff c5 6b d2 ?? 2b c2 48 63 c8 48 8b 44 24 ?? 42 ?? ?? ?? ?? ?? ?? ?? 41 32 0c 00 41 88 0c 18 49 ff c0 3b 6c 24 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CI_2147851265_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CI!MTB"
        threat_id = "2147851265"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {41 0f b6 03 03 c3 0f b6 c0 0f b6 8c 04 ?? ?? 00 00 80 c1 03 41 30 0a 49 ff c2 48 83 ef 01 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CI_2147851265_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CI!MTB"
        threat_id = "2147851265"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 eb 8b cb ff c3 d1 fa 8b c2 c1 e8 ?? 03 d0 6b c2 ?? 2b c8 48 63 c1 42 0f b6 04 10 41 30 40 ?? 49 83 e9 ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CI_2147851265_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CI!MTB"
        threat_id = "2147851265"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {46 88 24 30 49 ff c6 4c 89 75 ?? 49 81 fe ?? ?? ?? ?? 74 ?? 44 89 f0 83 e0 0f 47 0f b6 24 3e 44 32 64 05 ?? 4c 3b 75 00 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_MV_2147851301_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MV!MTB"
        threat_id = "2147851301"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {f0 00 22 00 0b 02 0e 24 00 22 24 00 00 7c 09 00 00 00 00 00 86 82 82 02 00 10}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_SPK_2147851425_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.SPK!MTB"
        threat_id = "2147851425"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {b8 ab aa aa 2a 4d 8d 40 01 41 f7 ea d1 fa 8b c2 c1 e8 1f 03 d0 41 8b c2 41 ff c2 8d 0c 52 c1 e1 02 2b c1 48 63 c8 0f b6 04 31 41 30 40 ff 49 83 eb 01 75}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_MX_2147851694_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MX!MTB"
        threat_id = "2147851694"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "AAFYhvbTzVckoxcPR" ascii //weight: 2
        $x_2_2 = "ABVboLxilZcIINJVD" ascii //weight: 2
        $x_2_3 = "ABXwWrCJUhRPmIgO" ascii //weight: 2
        $x_2_4 = "ABcqjwVeSzCeUC" ascii //weight: 2
        $x_2_5 = "ABxDadNtrUoMYg" ascii //weight: 2
        $x_2_6 = "ACHvJKFXQIXqtSbQdXbJIt" ascii //weight: 2
        $x_2_7 = "ACMAGlSoDQGnZITAvIiL" ascii //weight: 2
        $x_2_8 = "BJmqKPXnlNmNuJiYQ" ascii //weight: 2
        $x_2_9 = "BLTLaLFWoEmDksrHNRFrxCamT" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_MU_2147851699_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MU!MTB"
        threat_id = "2147851699"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {88 44 24 61 49 8b d7 8a 44 24 61 2a c3 34 54 88 44 24 62 8a 44 24 62 2a c3 32 c1 88 44 24 63 8a 44 24 63 2a c3 34 72 88 44 24 64}  //weight: 5, accuracy: High
        $x_5_2 = "\\Shellcode\\ReflectiveLoader.pdb" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_KLY_2147851713_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.KLY!MTB"
        threat_id = "2147851713"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {65 48 8b 04 25 60 00 00 00 48 8b 40 18 48 8b 48 10 48 8b 41 30 48 85 c0 0f 84 db 01 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CJ_2147851772_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CJ!MTB"
        threat_id = "2147851772"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {31 c1 48 8b 55 e0 8b 45 d4 48 98 88 0c 02 83 45 d4 01 83 7d d4}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_G_2147851906_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.G!MTB"
        threat_id = "2147851906"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 55 fc 8b 05 06 1e 00 00 39 c2 73 ?? 8b 45 fc 48 98 48 8d 15 76 1a 00 00 0f b6 04 10 83 f0 ?? 89 c1 8b 45 fc 48 98 48 8d 15 61 1a 00 00 88 0c 10 83 45 fc}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CBVV_2147852042_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CBVV!MTB"
        threat_id = "2147852042"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 b9 04 00 00 00 41 b8 00 30 00 00 ba 10 3a 04 00 33 c9 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_BU_2147852317_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.BU!MTB"
        threat_id = "2147852317"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {ba 80 03 00 00 41 b8 20 00 00 00 48 8b cb ff 15 [0-4] 85 c0 74 2f 48 c7 44 24 28 00 00 00 00 45 33 c9 4c 8b c3 c7 44 24 20 00 00 00 00 33 d2 33 c9 ff 15 [0-4] 48 8b c8 ba [0-4] ff 15}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CL_2147852366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CL!MTB"
        threat_id = "2147852366"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {42 0f b6 04 07 41 32 04 24 88 44 24 ?? 4c 8b 6e ?? 4c 8d 4c 24 ?? 4d 8b c5 48 8b d6 e8 ?? ?? ?? ?? 48 b9 ?? ?? ?? ?? ?? ?? ?? ?? 48 8b 54 24 ?? 48 2b ca 48 83 f9 ?? 0f 82 ?? ?? ?? ?? 48 ff c2 48 ?? ?? ?? ?? 48 89 46}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CBVO_2147852404_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CBVO!MTB"
        threat_id = "2147852404"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 42 38 44 8b 42 04 48 83 c2 ?? 89 c5 89 c1 c1 e8 ?? c1 c5 ?? c1 c1 ?? 31 e9 44 89 c5 31 c8 8b 4a fc 03 4a 20 c1 cd ?? 01 c8 44 89 c1 41 c1 e8 03 c1 c1 0e 31 e9 44 31 c1 01 c8 89 42 3c 48 39 d7 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_MD_2147852520_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MD!MTB"
        threat_id = "2147852520"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 0f b6 0c 0f 4c 8d 15 8c d6 03 00 47 0f b6 1c 02 47 0f b6 14 11 41 80 fb 0f 77 ?? 41 80 fa 0f 77 ?? 41 c1 e3 04 45 09 d3 48 39 d3 77}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 84 24 80 00 00 00 48 c7 40 08 12 00 00 00 48 8d 0d a0 08 02 00 48 89 08 ?? 48 8d 05 11 59 01 00 e8 ?? ?? ?? ?? 83 3d 25 63 12 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_MD_2147852520_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MD!MTB"
        threat_id = "2147852520"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {c1 ea 08 88 14 01 ff 05 ?? ?? ?? ?? 48 63 4b 7c 48 8b 83 c8 00 00 00 44 88 0c 01 ff 43 7c 8b 05 ?? ?? ?? ?? 8b 8b 94 00 00 00 05 4e 0b fb 28 03 0d ?? ?? ?? ?? 03 c8 89 0d ?? ?? ?? ?? 49 81 fa 30 44 04 00 0f 8c}  //weight: 5, accuracy: Low
        $x_5_2 = {33 83 98 00 00 00 83 e8 06 01 81 94 00 00 00 8b 83 a8 00 00 00 48 8b 15 ?? ?? ?? ?? 2d 05 d4 09 00 31 05}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CBYA_2147852764_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CBYA!MTB"
        threat_id = "2147852764"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f be 34 17 01 ce 89 f1 c1 e9 ?? 31 f1 0f be 74 17 01 01 ce 89 f1 c1 e9 ?? 31 f1 0f be 74 17 02 01 ce 89 f1 c1 e9 ?? 31 f1 0f be 74 17 03 01 ce 89 f1 c1 e9 ?? 31 f1 48 83 c2 ?? 49 39 d0 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CBYB_2147852821_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CBYB!MTB"
        threat_id = "2147852821"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 f7 e9 41 8b c9 41 ff c1 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 6b c2 ?? 2b c8 48 63 c1 0f b6 4c 04 ?? 41 30 4a ff 41 81 f9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_HT_2147852918_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.HT!MTB"
        threat_id = "2147852918"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 89 6c 24 30 48 8d 0d f0 9c 01 00 89 6c 24 28 45 33 c9 45 33 c0 c7 44 24 20 04 00 00 00 ba 00 00 00 80 48 89 9c 24 70 04 00 00 ff 15 2b 1d 01 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_IND_2147853352_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.IND!MTB"
        threat_id = "2147853352"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 89 c2 83 e2 07 0f b6 54 15 00 32 14 07 88 14 03 48 83 c0 01 48 39 c6 75 e6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CBYC_2147853369_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CBYC!MTB"
        threat_id = "2147853369"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 98 0f b6 44 05 d0 83 f0 ?? 89 c2 8b 85 ?? ?? ?? ?? 48 98 88 54 05 d0 83 85 ?? ?? ?? ?? 01 8b 85 ?? ?? ?? ?? 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_MY_2147853493_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MY!MTB"
        threat_id = "2147853493"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {66 89 45 0a 45 33 c0 ba 01 00 00 00 b9 02 00 00 00 ff 15 ?? ?? ?? ?? 48 89 45 38 41 b8 10 00 00 00 48 8d 55 08 48 8b 4d 38 ff 15}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CBYD_2147888127_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CBYD!MTB"
        threat_id = "2147888127"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 98 48 69 c8 ?? ?? ?? ?? 48 89 ca 48 c1 ea 3f 48 c1 e9 2d 01 d1 69 c9 ?? ?? ?? ?? 29 c8 30 03 48 8d 43 01 48 89 c3 48 39 f0 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_JN_2147888923_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.JN!MTB"
        threat_id = "2147888923"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 8a 44 0c ?? 41 8d 40 ?? 3c ?? 77 ?? 41 80 e8 ?? 44 88 44 0c ?? 48 ff c1 49 3b ca 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {41 8b c1 f7 d8 8d 3c 87 41 69 00 ?? ?? ?? ?? 49 83 c0 ?? 69 f6 ?? ?? ?? ?? 8b c8 c1 e9 ?? 33 c8 69 c9 ?? ?? ?? ?? 33 f1 49 83 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CCAA_2147889007_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CCAA!MTB"
        threat_id = "2147889007"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4d 8d 40 01 41 f7 e9 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 41 8b c1 41 ff c1 8d 0c d2 c1 e1 ?? 2b c1 48 98 0f b6 4c 04 50 41 30 48 ff 49 83 ea 01 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_RDG_2147889055_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.RDG!MTB"
        threat_id = "2147889055"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 63 4c 24 24 0f b6 04 08 33 44 24 34 88 c2 48 8b 44 24 28 48 63 4c 24 24 88 14 08 8b 44 24 24 83 c0 01}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CCAD_2147889128_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CCAD!MTB"
        threat_id = "2147889128"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 4c 24 08 48 89 54 24 10 4c 89 44 24 18 4c 89 4c 24 20 48 83 ec 28 b9 39 e2 94 f4 e8 ?? ?? ?? ?? 48 83 c4 28 48 8b 4c 24 08 48 8b 54 24 10 4c 8b 44 24 18 4c 8b 4c 24 20 4c 8b d1 0f 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_MZ_2147889304_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MZ!MTB"
        threat_id = "2147889304"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {31 f6 4c 89 c7 49 89 cc 49 89 d7 44 89 cb 48 8d ac 24 20 01 00 00 4c 8d 74 24 60 49 89 ed 4c 8d 44 24 48 49 8b 04 37 49 8d 0c 30 4c 89 f2 4c 89 44 24 28 48 83 c6 08 4a 89 44 06 f8}  //weight: 5, accuracy: High
        $x_5_2 = {41 89 c8 31 c9 45 0f be c0 44 89 c0 d3 f8 83 e0 01 88 04 0a 48 ff c1 48 83 f9 08 75 ec}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_H_2147889433_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.H!MTB"
        threat_id = "2147889433"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {4c 8b 44 24 ?? 48 8d 44 24 ?? 48 8b 4c 24 ?? 45 33 c9 ba 10 66 00 00 48 89 44 24 20 ff 15 ?? ?? ?? 00 85 c0 75 ?? ff 15 ?? ?? ?? 00 8b d0 48 8d 0d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CR_2147889462_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CR!MTB"
        threat_id = "2147889462"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 14 02 48 ff c0 45 31 db 4c 39 c8 4c 0f 42 d8 4c 89 59 ?? 41 32 10 eb ?? 4d 39 d0 0f 95 c0 48 83 c4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_RDH_2147889504_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.RDH!MTB"
        threat_id = "2147889504"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {41 8b c0 41 8b c8 2b c2 41 ff c0 d1 e8 03 c2 c1 e8 02 6b c0 07 2b c8 48 63 c1}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_SCD_2147889536_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.SCD!MTB"
        threat_id = "2147889536"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8d 50 02 48 89 55 10 0f b7 00 0f b6 c0 31 45 fc 8b 45 fc 69 c0 fb e3 ed 25 89 45 fc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_SCD_2147889536_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.SCD!MTB"
        threat_id = "2147889536"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {65 48 8b 04 25 60 00 00 00 48 8b 48 18 4c 8b 49 10 49 8b 49 30 48 85 c9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_I_2147890068_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.I!MTB"
        threat_id = "2147890068"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 98 0f b6 94 05 ?? 02 00 00 8b 85 ?? ?? 00 00 48 98 0f b6 84 05 b0 01 00 00 31 c2 8b 85 ?? ?? 00 00 48 98 88 54 05 b0 83 85}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CCAT_2147890133_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CCAT!MTB"
        threat_id = "2147890133"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "F9nvfGySrGLVnk4obTt52bEYghYj18Lt" ascii //weight: 1
        $x_1_2 = "JTTVZ3+7d5BsciqDp0mxgXUFXe+dsbP7" ascii //weight: 1
        $x_1_3 = "IBox8PGJdNtpqMOHsWd+FRwtrN2JAF7s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_J_2147890310_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.J!MTB"
        threat_id = "2147890310"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {44 8b c0 48 8d 5b ?? b8 ?? ?? ?? ?? 41 f7 e8 c1 fa ?? 8b ca c1 e9 ?? 03 d1 69 ca ?? ?? ?? ?? 44 2b c1 41 fe c0 44 32}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_MJA_2147890326_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MJA!MTB"
        threat_id = "2147890326"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 ee c1 fa 03 8b c2 c1 e8 1f 03 d0 8b c6 ff c6 6b d2 3b 2b c2 48 63 c8 48 8d 05 ?? ?? ?? ?? 8a 04 01 43 32 04 01 41 88 00 49 ff c0 3b f7 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_K_2147890458_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.K!MTB"
        threat_id = "2147890458"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {44 30 04 07 48 ff c0 49 39 c7}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CCAX_2147890465_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CCAX!MTB"
        threat_id = "2147890465"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 63 c8 41 ff c0 42 0f b6 04 09 30 02 48 ff c2 48 83 ee 01 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_ZJ_2147890494_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.ZJ!MTB"
        threat_id = "2147890494"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {42 8a 14 1e 48 89 f8 48 c1 f8 ?? 42 8a 0c 18 42 88 0c 1e 42 88 14 18 48 ff c6 4c 01 c7 49 39 f2 75 [0-64] 8a 0c 10 30 0c 3e ff c0 48 ff c6 49 39 f1 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_YAA_2147890556_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.YAA!MTB"
        threat_id = "2147890556"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 55 ff 0f b6 45 fe 01 d0 88 45 f7 0f b6 45 fe 88 45 ff 0f b6 45 fd 88 45 fe 0f b6 45 fd 00 45 f7}  //weight: 1, accuracy: High
        $x_1_2 = {0f b6 00 8b 55 f8 48 63 ca 48 8b 55 18 48 01 ca 32 45 f7 88 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_YAB_2147890557_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.YAB!MTB"
        threat_id = "2147890557"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 8b 44 24 ?? 48 63 0c 24 0f be 04 08 48 8b 4c 24 ?? 48 63 54 24 04 0f be 0c 11 31 c8 88 c2 48 8b 44 24 08 48 63 0c 24 88 14 08 8b 44 24 04 83 c0 01}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CCAY_2147890579_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CCAY!MTB"
        threat_id = "2147890579"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 c7 84 24 ?? ?? ?? ?? ?? ?? ?? ?? 48 8b 84 24 ?? ?? ?? ?? 48 6b d1 ?? 48 01 d0 48 83 f1 ?? 48 6b c9 ?? 48 01 c8 48 b9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_L_2147891209_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.L!MTB"
        threat_id = "2147891209"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 63 c8 41 ff c0 48 8b 84 24 ?? ?? ?? ?? 42 0f b6 14 11 41 32 14 19 41 88 14 01 49 ff c1 44 3b 84 24}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_M_2147891355_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.M!MTB"
        threat_id = "2147891355"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 84 3d ?? ?? ?? ?? 43 8b 54 84 ?? 48 ff c7 41 02 c2 02 c2 49 3b fb 44 0f b6 d0 49 0f 4d fd 49 ff c0 43 8b 44 94 ?? 43 89 44 84 ?? 43 89 54 94}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_PZ_2147891379_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.PZ!MTB"
        threat_id = "2147891379"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b f0 65 48 8b 0c 25 60 00 00 00 48 8b 49 18 48 8b 49 10 4c 8b 59 30}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_BRV_2147891381_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.BRV!MTB"
        threat_id = "2147891381"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CallDLLDynamic.pdb" ascii //weight: 1
        $x_1_2 = "per_thread_data.cpp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CTX_2147891411_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CTX!MTB"
        threat_id = "2147891411"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 ff c0 f7 ed c1 fa 02 8b c2 c1 e8 1f 03 d0 8b c5 ff c5 8d 0c d2 03 c9 2b c1 48 63 c8 48 8b 44 24 38 42 0f b6 8c 31 e0 eb 00 00 41 32 4c 00 ff 41 88 4c 18 ff 3b 6c 24 30 72 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_N_2147891433_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.N!MTB"
        threat_id = "2147891433"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b c2 48 8d 4d f4 48 03 c8 ff c2 0f b6 01 41 2a c1 41 32 c0 88 01}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CXT_2147891491_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CXT!MTB"
        threat_id = "2147891491"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 ff c0 f7 ed c1 fa 02 8b c2 c1 e8 1f 03 d0 8b c5 ff c5 6b d2 15 2b c2 48 63 c8 48 8b 44 24 38 42 0f b6 8c 31 ?? ?? ?? ?? 41 32 4c 00 ff 41 88 4c 18 ff 3b 6c 24 30 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_FSS_2147891821_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.FSS!MTB"
        threat_id = "2147891821"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 c8 89 0d f5 24 02 00 48 63 4b 6c 48 8b 83 ?? ?? ?? ?? 88 14 01 41 8b d0 ff 43 6c 48 8b 0d 9e 24 02 00 8b 05 a8 24 02 00 c1 ea 08 31 41 2c 8b 05 30 25 02 00 8b 4b 28 05 aa 12 f4 ff 03 c8 48 8b 05 4b 25 02 00 89 0d 19 25 02 00 48 63 0d ea 24 02 00 88 14 01 ff 05 e1 24 02 00 48 8b 05 5e 24 02 00 8b 88 ?? ?? ?? ?? 03 4b 48 81 f1 97 60 13 00 29 4b 28 8b 05}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_DB_2147891935_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.DB!MTB"
        threat_id = "2147891935"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 11 0f b6 c2 41 32 c0 88 01 44 0f b6 c2 48 ff c1 49 3b c9 72 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_DB_2147891935_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.DB!MTB"
        threat_id = "2147891935"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 88 04 01 b8 ?? ?? ?? ?? 8b 8b ?? ?? ?? ?? 33 8b ?? ?? ?? ?? ff 43 ?? 2b c1 01 05 ?? ?? ?? ?? b8 ?? ?? ?? ?? 2b 83 ?? ?? ?? ?? 01 83 ?? ?? ?? ?? b8 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? 01 43 ?? 49 ?? ?? ?? ?? ?? ?? 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_DC_2147892050_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.DC!MTB"
        threat_id = "2147892050"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff c0 89 04 24 8b 44 24 ?? 39 04 24 73 ?? 8b 04 24 0f b6 4c 24 ?? 48 8b 54 24 ?? 0f be 04 02 33 c1 8b 0c 24 48 8b 54 24 ?? 88 04 0a eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CCBV_2147892099_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CCBV!MTB"
        threat_id = "2147892099"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 f7 e8 d1 fa 8b c2 c1 e8 ?? 03 d0 41 8b c0 41 ff c0 8d 0c 52 c1 e1 ?? 2b c1 48 63 c8 42 0f b6 04 19 41 30 42 ff 45 3b c1 7c}  //weight: 1, accuracy: Low
        $x_1_2 = "[*] Executing" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_YAD_2147892294_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.YAD!MTB"
        threat_id = "2147892294"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 4a 60 0f af c8 89 4a 60 8b 05 a5 63 04 00 48 8b 0d d6 63 04 00 41 31 04 0e 49 83 c6 04 44 8b 0d b7 63 04 00 4c 8b 05 f8 62 04 00 41 81 c1 5c 49 ed ff 8b 15 d3 63 04 00 44 03 ca}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_YAD_2147892294_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.YAD!MTB"
        threat_id = "2147892294"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 83 94 00 00 00 8b 8b 20 01 00 00 ff c1 0f af c1 89 83 94 00 00 00 48 8b 05 ?? ?? ?? ?? 8b 0c 02 33 4b 6c 48 8b 83 c8 00 00 00 89 0c 02 48 83 c2 04 48 8b 05 ?? ?? ?? ?? 8b 88 c0 00 00 00 81 c1 73 81 e0 ff 03 4b 1c 09 8b 90 00 00 00 8b 83 90 00 00 00 83 f0 01}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_YAC_2147892418_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.YAC!MTB"
        threat_id = "2147892418"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {01 43 1c 48 8b 83 ?? ?? ?? ?? 48 63 4b 68 45 8b 04 01 49 83 c1 04 8b 05 ?? ?? ?? ?? 05 db c6 f2 ff 01 03 8b 15 82 32 07 00 8b 83 90 00 00 00 81 c2 ?? ?? ?? ?? 03 93 e0 00 00 00 0f af c2 0f b6 53 58 89 83 90 00 00 00 41 0f b6 c0 0f af d0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_ZK_2147892643_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.ZK!MTB"
        threat_id = "2147892643"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {65 4c 8b 04 25 60 00 00 00 4d 8b 40 18 4d 8b 40 20 4d 89 c3 49 8b 50 50 51 4c 89 d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_ZK_2147892643_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.ZK!MTB"
        threat_id = "2147892643"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {41 f7 e8 41 03 d0 c1 fa 05 8b c2 c1 e8 1f 03 d0 b8 ?? ?? ?? ?? 2a c2 0f be c0 6b c8 ?? 41 02 c8 41 ff c0 41 30 09 49 ff c1 41 83 f8 16 7c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_O_2147893134_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.O!MTB"
        threat_id = "2147893134"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {44 8b f8 85 c0 78 ?? 48 83 c6 06 48 ff}  //weight: 2, accuracy: Low
        $x_2_2 = {49 8b ce 4c 8b c6 ff 15}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_LKBA_2147893357_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.LKBA!MTB"
        threat_id = "2147893357"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 8d 0c 00 47 8d 0c 89 41 89 d2 45 29 ca 41 80 ca ?? 46 88 54 04 2a 49 ff c0 83 c2 ?? 83 fa 12 77}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_ZL_2147893896_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.ZL!MTB"
        threat_id = "2147893896"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 04 3b 30 06 48 ff c6 48 ff c3 48 ff c9 80 fb 28 75 03 48 33 db 83 f9 00 7f}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_ZL_2147893896_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.ZL!MTB"
        threat_id = "2147893896"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 44 24 60 bb 03 00 00 00 48 8b 4c 24 70 31 ff be 00 80 00 00 49 89 f8 49 89 f9 49 89 fa e8 f2 b4 fc ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_ZL_2147893896_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.ZL!MTB"
        threat_id = "2147893896"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {49 ff c5 40 88 2c 30 48 ff c6 48 89 74 24 ?? 4d 39 ef 74 2d 44 89 e9 83 e1 ?? 42 0f b6 2c 21 42 32 2c 2f 48 3b 74 24 ?? 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_LKBE_2147893899_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.LKBE!MTB"
        threat_id = "2147893899"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b9 aa 26 00 00 31 d2 41 b9 5c 00 00 00 f7 f1 c7 44 24 50 5c 00 00 00 c7 44 24 48 65 00 00 00 c7 44 24 40 70 00 00 00 c7 44 24 38 69 00 00 00 c7 44 24 30 70 00 00 00 c7 44 24 28 5c 00 00 00 c7 44 24 20 2e 00 00 00 41 b8 5c 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_ZO_2147894018_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.ZO!MTB"
        threat_id = "2147894018"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {ff c0 89 84 24 ?? ?? ?? ?? 8b 44 24 ?? 39 84 24 ?? ?? ?? ?? 7d ?? 48 63 84 24 ?? ?? ?? ?? 48 8b 4c 24 ?? 0f b6 04 01 83 f0 ?? 48 63 8c 24 ?? ?? ?? ?? 48 8b 54 24 ?? 88 04 0a eb ?? c7 84 24 ?? ?? ?? ?? ?? ?? ?? ?? eb ?? 8b 84 24 ?? ?? ?? ?? ff c0 89 84 24 ?? ?? ?? ?? 8b 44 24 ?? 39 84 24 ?? ?? ?? ?? 7d ?? 48 63 84 24 ?? ?? ?? ?? 48 8b 4c 24 ?? 0f b6 04 01 83 f0 ?? 48 63 8c 24 ?? ?? ?? ?? 48 8b 54 24 ?? 88 04 0a eb}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_YY_2147894073_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.YY!MTB"
        threat_id = "2147894073"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 0f b6 74 3d 00 41 30 de e8 ?? ?? ?? ?? 99 f7 fe fe c2 44 30 f2 41 88 14 3f 48 ff c7 49 39 fc 75}  //weight: 1, accuracy: Low
        $x_1_2 = {41 0f b6 1c 3f 44 30 f3 41 88 1c 3f e8 ?? ?? ?? ?? 99 f7 fe fe c2 30 da 41 88 14 3f 48 ff c7 48 39 fe 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_HOD_2147894362_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.HOD!MTB"
        threat_id = "2147894362"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 04 01 89 84 24 48 01 00 00 8b 44 24 48 99 b9 25 00 00 00 f7 f9 8b c2 48 98 48 8b 4c 24 20 0f b6 04 01 8b 8c 24 48 01 00 00 33 c8 8b c1 48 63 4c 24 48 48 8b 54 24 28 88 04 0a eb 9f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_PABK_2147894561_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.PABK!MTB"
        threat_id = "2147894561"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b d1 41 8b c0 b9 40 00 00 00 83 e0 3f 2b c8 33 c0 48 d3 c8 49 33 c0 48 39 05 8e 9e 0c 00 75 12}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_KI_2147894667_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.KI!MTB"
        threat_id = "2147894667"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4d 8b c1 48 b8 ?? ?? ?? ?? ?? ?? ?? ?? 49 f7 e1 48 c1 ea ?? 48 6b c2 ?? 4c 2b c0 43 8a 04 10 41 30 04 09 49 ff c1 4d 3b cb 76}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_RAZ_2147894707_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.RAZ!MTB"
        threat_id = "2147894707"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b8 e1 83 0f 3e 41 f7 e8 c1 fa 04 8b c2 c1 e8 1f 03 d0 6b d2 42 41 8b c0 2b c2 48 63 c8 42 0f b6 04 19 43 32 04 0a 41 88 01 41 ff c0 49 ff c1 41 81 f8 09 0e 04 00 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_ARA_2147895086_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.ARA!MTB"
        threat_id = "2147895086"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {41 88 45 00 49 8b c3 48 c1 f8 10 0f b6 d0 c1 f9 10 42 0f b6 84 32 20 79 00 00 32 c1 41 8b c8}  //weight: 2, accuracy: High
        $x_2_2 = {41 0f b6 0c 00 ff c2 30 08 48 8d 40 01 3b 93 d0 03 00 00 7c eb}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_YAG_2147895128_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.YAG!MTB"
        threat_id = "2147895128"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2d 00 04 00 00 0f ba f8 0a 41 88 04 24 49 ff c4 49 83 ff 10 72 31 49 8d 57 01 48 8b c3 48 81 fa 00 10 00 00 72 19 48 83 c2 27 48 8b 5b f8 48 2b c3 48 83 c0 f8 48 83 f8 1f 0f 87 ?? ?? ?? ?? 48 8b cb}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_YAG_2147895128_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.YAG!MTB"
        threat_id = "2147895128"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {32 d0 c1 c2 08 e9 ce a4 01 00 e9}  //weight: 10, accuracy: High
        $x_1_2 = {48 c7 04 24 65 00 00 00 48 ?? ?? ?? ?? 78 00 00 00 48 ?? ?? ?? ?? 70 00 00 00 48 ?? ?? ?? ?? 6c 00 00 00 48 ?? ?? ?? ?? 6f 00 00 00 48 ?? ?? ?? ?? 72 00 00 00 48 c7 44 24 06 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_YAH_2147895233_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.YAH!MTB"
        threat_id = "2147895233"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2d 00 04 00 00 0f ba f8 0a 41 88 04 24 49 ff c4 84 db 74 31 49 8d 55 01 48 8b c7 48 81 fa 00 10 00 00 72 19 48 83 c2 27 48 8b 7f f8 48 2b c7 48 83 c0 f8 48 83 f8 1f 0f 87 ?? ?? ?? ?? 48 8b cf e8 ?? ?? ?? ?? 41 ff c6 48 ff c6 41 81 fe 58 1b 00 00 bb}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_P_2147895316_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.P!MTB"
        threat_id = "2147895316"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {80 74 3c 70 58 48 8d 0d 14 23 00 00 0f b6 54 3c 70 e8 ?? ?? ?? ?? 48 ff c7 48 81 ff}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_YAI_2147895521_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.YAI!MTB"
        threat_id = "2147895521"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff cf 81 cf ?? ?? ?? ?? ff c7 48 63 cf 48 8d 54 24 40 48 03 d1 0f b6 0a 41 88 08 44 88 0a 41 0f b6 10 49 03 d1 0f b6 ca 0f b6 54 0c 40 41 30 12 49 ff c2 49 83 eb 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_DWE_2147895537_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.DWE!MTB"
        threat_id = "2147895537"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 0c 10 48 8d 40 01 80 e9 2d 88 48 ff 48 83 eb 01 75 ec}  //weight: 1, accuracy: High
        $x_1_2 = {41 0f b6 04 3a 41 8d 49 01 42 32 04 02 45 33 c9 88 07 48 8d 7f 01 83 f9 25 48 8d 42 01 44 0f 4e c9 33 d2 83 f9 25 48 0f 4e d0 49 83 eb 01 75 d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_LKBF_2147895547_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.LKBF!MTB"
        threat_id = "2147895547"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 73 65 72 73 5c 41 70 6f 63 61 6c 79 70 73 65 5c [0-128] 5c 52 75 73 74 5c 63 6c 69 65 6e 74 5c 31 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_2 = "57k7w2hd52.8pfyh.ws:8443/TseNn7" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_LKBG_2147895548_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.LKBG!MTB"
        threat_id = "2147895548"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3b d3 7d 17 41 0f b6 0c 06 ff c2 30 08 48 ff c0 48 8b c8 48 2b ce 48 3b cf 7c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_Q_2147895576_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.Q!MTB"
        threat_id = "2147895576"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {4c 8b 45 88 48 8d 45 ?? 48 8b 4d ?? 45 33 c9 ba 10 66 00 00 48 89 44 24 20 ff 15}  //weight: 2, accuracy: Low
        $x_2_2 = {48 8d 44 24 ?? 48 89 44 24 ?? 45 33 c9 48 8d 45 ?? 45 33 c0 33 d2 48 89 44 24 20 ff 15}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_KH_2147895787_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.KH!MTB"
        threat_id = "2147895787"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 88 0c 0a 99 41 f7 f9 48 63 d2 0f b6 04 17 41 88 04 0b 48 83 c1 ?? 48 81 f9}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 d2 0f b6 84 14 ?? ?? ?? ?? 40 88 bc 14 ?? ?? ?? ?? 88 84 0c ?? ?? ?? ?? 02 84 14 ?? ?? ?? ?? 0f b6 c0 0f b6 84 04 ?? ?? ?? ?? 42 32 04 0e 43 88 04 08 49 83 c1 ?? 4c 39 cb 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_KH_2147895787_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.KH!MTB"
        threat_id = "2147895787"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 d8 48 ff c5 e8 ?? ?? ?? ?? 0f b7 db 48 8d 0d ?? ?? ?? ?? 2b d8 8b c6 c1 c8 ?? 03 d8 e8 ?? ?? ?? ?? 48 8d 0d ?? ?? ?? ?? 2b d8 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {03 d8 48 8d 0d ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 8d 0d ?? ?? ?? ?? 03 d8 e8 ?? ?? ?? ?? 48 8d 0d ?? ?? ?? ?? 03 d8 e8 ?? ?? ?? ?? 03 c3 33 f0 80 7d ?? ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_HNH_2147895822_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.HNH!MTB"
        threat_id = "2147895822"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff 15 50 30 00 10 8b d8 8d 6d 28 8b 44 24 10 40 6a 00 89 44 24 14 59 66 3b 46 06 72 cc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_ZR_2147896285_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.ZR!MTB"
        threat_id = "2147896285"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {03 c8 09 8b ?? ?? ?? ?? 48 8b 05 ?? ?? ?? ?? 48 8b 88 ?? ?? ?? ?? 48 8b 83 ?? ?? ?? ?? 42 8b 14 09 33 15 ?? ?? ?? ?? 41 89 14 01 49 83 c1 ?? 8b 05 ?? ?? ?? ?? 29 83 ?? ?? ?? ?? 8b 4b ?? 03 8b ?? ?? ?? ?? 8b 05 ?? ?? ?? ?? 05 ?? ?? ?? ?? 03 c8 89 0d ?? ?? ?? ?? 8b 83 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? 49 81 f9 ?? ?? ?? ?? 7c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_ZR_2147896285_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.ZR!MTB"
        threat_id = "2147896285"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 00 6d 00 70 00 6f 00 72 00 74 00 20 00 72 00 65 00 71 00 75 00 65 00 73 00 74 00 73 00 3b 00 65 00 78 00 65 00 63 00 28 00 72 00 65 00 71 00 75 00 65 00 73 00 74 00 73 00 2e 00 67 00 65 00 74 00 28 00 27 00 [0-32] 2f 00 74 00 65 00 6e 00 2e 00 6e 00 6f 00 69 00 74 00 63 00 65 00 6c 00 6c 00 6f 00 63 00 2d 00 65 00 67 00 64 00 65 00 73 00 6d 00 2e 00 65 00 64 00 61 00 72 00 67 00 70 00 75 00 2f 00 2f 00 3a 00 70 00 74 00 74 00 68 00 27 00 5b 00 3a 00 3a 00 2d 00 31 00 5d 00 2c 00 68 00 65 00 61 00 64 00 65 00 72 00 73 00}  //weight: 1, accuracy: Low
        $x_1_2 = "gogogo" wide //weight: 1
        $x_1_3 = "-oC:\\Users\\Public\\Documents\\ -pxpython379x -y" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_MO_2147896309_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MO!MTB"
        threat_id = "2147896309"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 6c 24 78 48 8d 6c 24 78 48 89 84 24 88 00 00 00 4c 89 84 24 b0 00 00 00 48 89 bc 24 a0 00 00 00 48 89 b4 24 a8 00 00 00 e8 ?? ?? ?? ?? 0f 1f 00 48 85 c9 0f 85 04 01 00 00 ?? b9 0c 00 00 00 bf 10 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = "VvZdx8kyDx8wCZeWRbsK" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_MO_2147896309_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MO!MTB"
        threat_id = "2147896309"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 63 53 6c 48 8b 05 ?? ?? ?? ?? 45 8b c1 41 c1 e8 10 48 8b 88 c0 00 00 00 44 88 04 0a 41 8b d1 ff 43 6c 48 8b 05 ?? ?? ?? ?? c1 ea 08 48 63 48 6c 48 8b 80 c0 00 00 00 88 14 01}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 0d 70 8b 01 00 83 e8 56 31 41 74 48 8b 05 ?? ?? ?? ?? 8b 88 e0 00 00 00 b8 bd 8c 08 00 33 0d ?? ?? ?? ?? 2b c1 01 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_GAT_2147896339_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.GAT!MTB"
        threat_id = "2147896339"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff c2 48 63 c2 48 8d 8c 24 60 05 00 00 48 03 c8 0f b6 01 41 88 04 30 44 88 09 41 0f b6 0c 30 49 03 c9 0f b6 c1 0f b6 8c 04 60 05 00 00 41 30 0a 49 ff c2 49 83 eb 01 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_ZQ_2147896444_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.ZQ!MTB"
        threat_id = "2147896444"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {f7 eb 03 d3 c1 fa 05 8b c2 c1 e8 1f 03 d0 0f be c2 6b d0 ?? 0f b6 c3 2a c2 04 ?? 41 30 00 ff c3 4d 8d 40 01 83 fb 12 7c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_MK_2147896791_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MK!MTB"
        threat_id = "2147896791"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {ff c9 48 8b 54 24 68 8b 84 02 00 01 00 00 2b c1 b9 [0-4] 48 6b c9 03 48 8b 54 24 68 89 84 0a 00 01 00 00 e9}  //weight: 5, accuracy: Low
        $x_5_2 = {33 c8 8b c1 48 8b 4c 24 68 89 41 50 48 8b 44 24 68 48 63 40 7c 48 8b 4c 24 68 48 8b 89 [0-4] 0f b6 54 24 30 88 14 01 48 8b 44 24 68 8b 40 7c ff c0}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_MK_2147896791_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MK!MTB"
        threat_id = "2147896791"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 89 ee 48 89 74 24 48 49 89 f6 89 ee 49 8b 4d 00 46 8d 04 f5 00 00 00 00 c7 44 24 20 03 00 00 00 48 89 fa 4d 89 e1 e8}  //weight: 2, accuracy: High
        $x_1_2 = {78 78 78 78 2e 64 6c 6c 00 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 00 52 75 6e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_YAJ_2147896979_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.YAJ!MTB"
        threat_id = "2147896979"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {86 d2 32 c3 86 db 86 c0 c0 c8 29 90 aa 90 90 48 ff c9 90 86 db ac 32 c3 90 02 c3 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_YAK_2147897068_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.YAK!MTB"
        threat_id = "2147897068"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 ff c9 e9 05 00 48 ff c9 ac 32 c3 02 c3 32 c3 c0 c8 ca aa 48 ff c9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CCEI_2147897198_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CCEI!MTB"
        threat_id = "2147897198"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ba 09 0e 04 00 44 8d 49 40 41 b8 00 10 00 00 ff 15 ?? ?? ?? ?? 41 b8 09 0e 04 00 48 8d 94 24 ?? ?? ?? ?? 48 8b c8 48 8b d8 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_R_2147897405_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.R!MTB"
        threat_id = "2147897405"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {49 63 c0 48 8d 8d ?? ?? ?? ?? 48 03 c8 0f b6 01 41 88 01 44 88 11 41 0f b6 01 41 03 c2 0f b6 c0 0f b6 8c 05 ?? ?? ?? ?? 41 30 0b 49 ff c3 48 83 eb}  //weight: 2, accuracy: Low
        $x_2_2 = {48 8b 4c 24 ?? 8b d1 2b d0 48 c1 e8 ?? 44 8b 44 24 ?? 44 2b c0 8b c2 99 33 c2 2b c2}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_CobaltStrike_YAM_2147897548_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.YAM!MTB"
        threat_id = "2147897548"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 8b cc 41 b8 ?? ?? ?? ?? 49 8b c2 0f 1f 44 00 00 0f b7 00 41 8b c8 c1 c9 08 41 ff c1 03 c8 41 8b c1 49 03 c2 44 33 c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_YAN_2147897553_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.YAN!MTB"
        threat_id = "2147897553"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b c1 83 c0 ff 48 8b 8c 24 ?? ?? ?? ?? 8b 49 50 33 c8 8b c1 48 8b 8c 24 f0 00 00 00 89 41 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_ZT_2147897599_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.ZT!MTB"
        threat_id = "2147897599"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 8b 8c 24 ?? ?? ?? ?? 89 81 ?? ?? ?? ?? 8b 44 24 ?? c1 e8 10 48 8b 8c 24 ?? ?? ?? ?? 48 63 89 ?? ?? ?? ?? 48 8b 94 24 ?? ?? ?? ?? 48 8b 92 ?? ?? ?? ?? 88 04 0a 48 8b 84 24 ?? ?? ?? ?? 8b 80 ?? ?? ?? ?? ff c0 48 8b 8c 24 ?? ?? ?? ?? 89 81 ?? ?? ?? ?? 8b 44 24 ?? c1 e8 08 48 8b 0d ?? ?? ?? ?? 48 63 89 ?? ?? ?? ?? 48 8b 15 ?? ?? ?? ?? 88 04 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_HM_2147897656_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.HM!MTB"
        threat_id = "2147897656"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CP71.DLL" wide //weight: 1
        $x_1_2 = "Mark\\NewVirus\\CPP\\msedge\\x64\\Release\\msedge.pdb" ascii //weight: 1
        $x_1_3 = "ExportSpartanCookies" ascii //weight: 1
        $x_1_4 = "msedge.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_YAO_2147897744_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.YAO!MTB"
        threat_id = "2147897744"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fe c3 8a 94 1d ?? ?? ?? ?? 02 c2 8a 8c 05 ?? ?? ?? ?? 88 8c 1d ?? ?? ?? ?? 88 94 05 ?? ?? ?? ?? 02 ca 8a 8c 0d ?? ?? ?? ?? 30 0e e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_HS_2147898344_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.HS!MTB"
        threat_id = "2147898344"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 8b 19 41 f7 f2 4d 01 cb 49 ff c1 89 d2 8a 44 11 ?? 41 30 03 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_HS_2147898344_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.HS!MTB"
        threat_id = "2147898344"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 c3 4c 8b 2d ?? ?? ?? ?? 31 f6 39 f7 7e ?? 48 89 f0 83 e0 ?? 41 8a 04 04 32 44 35 ?? 88 04 33 48 ff c6 41 ff d5 41 ff d5 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_HS_2147898344_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.HS!MTB"
        threat_id = "2147898344"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "http://www.flntp.ro/fintp.x64.bin" ascii //weight: 3
        $x_1_2 = "Updating application" ascii //weight: 1
        $x_2_3 = "ConsoleApplication6.pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_AKSM_2147898399_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.AKSM!MTB"
        threat_id = "2147898399"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {65 48 8b 04 25 60 00 00 00 48 8b 48 18 48 83 c1 10}  //weight: 1, accuracy: High
        $x_1_2 = "systeminfo.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CCEY_2147898451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CCEY!MTB"
        threat_id = "2147898451"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 4c 24 48 48 8d 44 24 30 45 33 c9 48 89 44 24 28 33 d2 48 89 5c 24 20 45 8d 41 01 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {48 8d be 08 01 00 00 48 89 7c 24 30 8b 56 50 41 b9 40 00 00 00 41 b8 00 30 00 00 48 8b 4e 30 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_SPR_2147898679_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.SPR!MTB"
        threat_id = "2147898679"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {48 83 f8 64 4d 8d 40 01 49 0f 44 c3 41 ff c2 0f b6 4c 04 30 48 ff c0 41 30 48 ff 49 63 ca 48 81 f9}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_UH_2147898722_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.UH!MTB"
        threat_id = "2147898722"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 04 01 66 89 04 24 8b 44 24 ?? ff c0 89 44 24 ?? 0f b7 04 24 8b 4c 24 ?? c1 e9 ?? 8b 54 24 ?? c1 e2 ?? 0b ca 03 c1 8b 4c 24 ?? 33 c8 8b c1 89 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CCFD_2147898761_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CCFD!MTB"
        threat_id = "2147898761"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 0b 4c 8d 44 24 ?? 4c 63 cf 33 d2 4c 03 cd ff 15 ?? ?? ?? ?? 85 c0 78 ?? 83 c7 ?? ff c6 48 83 c3 ?? 49 3b de 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_EAF_2147898772_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.EAF!MTB"
        threat_id = "2147898772"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {49 83 c2 02 48 8b bc 24 ?? ?? ?? ?? 49 83 c1 08 48 8b 9c 24 ?? ?? ?? ?? 4c 8b 9c 24 a0 00 00 00 89 04 91 48 8b 05 3d b2 07 00 48 8b 15 ?? ?? ?? ?? 4c 89 54 24 70 4c 89 4c 24 68 8a 4c 47 01 4b 8d 04 64 30 0c 10 8b 84 24 48 01 00 00 48 8b 54 24 60 41 03 c6 89 84 24 ?? ?? ?? ?? 3d a0 0b 00 00 0f 8f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_BMC_2147898851_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.BMC!MTB"
        threat_id = "2147898851"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dfbfdhbfddfbfdnhdfhfd.fll" ascii //weight: 1
        $x_1_2 = {65 48 8b 04 25 30 00 00 00 48 8b 40 60}  //weight: 1, accuracy: High
        $x_1_3 = {48 8b 40 18}  //weight: 1, accuracy: High
        $x_1_4 = {48 8b 48 10 8a e4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_PABP_2147899053_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.PABP!MTB"
        threat_id = "2147899053"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 6b d0 64 0f 57 c0 f2 48 0f 2a c7 66 0f 2f c6 41 0f 97 c0 49 8b ce 45 84 c0 48 0f 44 cf 48 03 ca 49 8b c7 48 f7 e9 48 c1 fa 1a 48 8b c2 48 c1 e8 3f 48 03 d0 48 89 54 24 28 48 69 c2 00 ca 9a 3b 48 2b c8 89 4c 24 30}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_PACC_2147899057_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.PACC!MTB"
        threat_id = "2147899057"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 63 c9 f0 80 34 19 39 41 ff c1 44 3b ce 72 f0}  //weight: 1, accuracy: High
        $x_1_2 = "PAYLOAD_BIN" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_LKBH_2147899306_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.LKBH!MTB"
        threat_id = "2147899306"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 b8 5f 01 c5 88 b2 7d dc 64}  //weight: 1, accuracy: High
        $x_1_2 = {48 b8 41 07 6f 48 ba c2 a3 68}  //weight: 1, accuracy: High
        $x_1_3 = {48 b8 37 6a fb 46 10 cb 8b 85}  //weight: 1, accuracy: High
        $x_1_4 = {48 b8 cb 1b 55 4e 17 fa a2 c6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CCFN_2147899680_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CCFN!MTB"
        threat_id = "2147899680"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 83 f1 01 49 ff c0 42 03 44 8c ?? 3d ?? ?? ?? ?? 7d ?? 41 0f b6 0c 38 48 63 d0 42 88 0c 1a eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CN_2147899919_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CN!MTB"
        threat_id = "2147899919"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 83 c0 01 0f b7 04 01 41 89 d1 41 c1 c9 ?? 44 01 c8 31 c2 44 89 c0 80 3c 01 ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_DF_2147899922_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.DF!MTB"
        threat_id = "2147899922"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 4c 03 ?? 48 ff c0 41 3a 4c 03 ?? 0f 85 ?? ?? ?? ?? 48 83 f8 ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {30 10 ff c1 48 8d 40 ?? 83 f9 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_ZI_2147900012_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.ZI!MTB"
        threat_id = "2147900012"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 c3 48 8d 0d ?? ?? ?? ?? e8 a7 ab 00 00 01 d8 31 45 ?? 8b 55 ?? 48 8b 45 ?? 48 01 d0 0f b6 00 84 c0 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {01 d8 66 89 45 ?? 0f b7 45 ?? 8b 55 ?? c1 ca ?? 8d 1c 10 48 8d 0d ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_MIP_2147900079_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MIP!MTB"
        threat_id = "2147900079"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 4c 04 4d 41 30 4c 06 fd 0f b6 4c 04 4e 41 30 4c 06 fe 0f b6 4c 04 4f 41 30 4c 06 ff 0f b6 4c 04 50 41 30 0c 06 48 83 c0 10 48 83 f8 7f 0f 85 53 ff ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {32 44 24 44 43 88 44 2e 0c 0f b6 44 24 2d 32 44 24 45 43 88 44 2e 0d 0f b6 44 24 2e 32 44 24 46 43 88 44 2e 0e 0f b6 44 24 2f 32 44 24 47 43 88 44 2e 0f 0f 29 44 24 20 48 8b 05 88 c3 02 00 0f b6 00 3c 01 0f 85 a5 fe ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_MIH_2147900080_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MIH!MTB"
        threat_id = "2147900080"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 03 d1 48 8b ca 8b 14 24 c1 ea ?? 81 e2 ff 00 00 00 8b d2 33 04 91 b9 00 04 00 00 48 6b c9 ?? 48 8d 15 15 69 01 00 48 03 d1 48 8b ca 8b 14 24 c1 ea 18 8b d2 33 04 91 89 04 24 48 8b 44 24 30 48 83 e8 04 48 89 44 24 30 e9 25}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_YAR_2147900469_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.YAR!MTB"
        threat_id = "2147900469"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 75 b0 43 80 75 b1 6c 80 75 b2 6f 80 75 b3 73 80 75 b4 65 80 75 b5 48 80 75 b6 61 80 75 b7 6e 80 75 b8 64 80 75 b9 6c 80 75 ba 65 80 75 bb 43 80 75 bc 6c 80 75 bd 6f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_RB_2147900503_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.RB!MTB"
        threat_id = "2147900503"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 63 ca 83 c2 01 0f b6 4c 0c ?? 30 08 48 8d 48 ?? 49 39 c8 74 1f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_WJ_2147900542_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.WJ!MTB"
        threat_id = "2147900542"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c1 83 e0 ?? 83 e1 ?? 99 41 01 c8 41 f7 f8 01 c8 69 c0 ?? ?? ?? ?? 45 31 c0 31 c9 ba ?? ?? ?? ?? 48 98 48 6b c0 ?? 48 89 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_AMBA_2147900546_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.AMBA!MTB"
        threat_id = "2147900546"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 c2 83 e2 ?? 8a 54 15 ?? 32 14 07 41 88 14 00 48 ff c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_PACZ_2147900711_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.PACZ!MTB"
        threat_id = "2147900711"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 8b 55 10 48 8b 45 f8 48 01 d0 0f b6 00 89 c1 48 8b 45 f8 ba ?? ?? ?? ?? 48 f7 75 f0 48 8b 45 20 48 01 d0 0f b6 00 31 c1 48 8b 55 10 48 8b 45 f8 48 01 d0 89 ca 88 10 48 83 45 f8 01 48 8b 45 f8 48 3b 45 18 72 b9}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CCGQ_2147900712_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CCGQ!MTB"
        threat_id = "2147900712"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 0c 03 02 4c 04 ?? 80 c1 ?? 80 f1 ?? 88 4c ?? 40 48 ff c0 48 83 f8 ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_JV_2147901126_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.JV!MTB"
        threat_id = "2147901126"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 c2 83 e2 ?? 41 8a 14 14 32 54 05 ?? 88 14 06 48 ff c0 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_JV_2147901126_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.JV!MTB"
        threat_id = "2147901126"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 00 30 01 48 83 c1 ?? 48 39 d1 74 ?? 49 63 c2 4c 39 c8 75 ?? 4c 89 c0 41 ba ?? ?? ?? ?? 0f b6 00 30 01 48 83 c1 ?? 48 39 d1 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_S_2147901228_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.S!MTB"
        threat_id = "2147901228"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 04 24 0f b6 4c 24 ?? 48 8b 54 24 ?? 0f be 04 02 33 c1 8b 0c 24 48 8b 54 24 ?? 88 04 0a}  //weight: 2, accuracy: Low
        $x_2_2 = {0f be 00 8b 4c 24 ?? 03 c8 8b c1 89 44 24 ?? 48 8b 44 24 ?? 48 ff c0 48 89 44 24 ?? 48 8b 44 24}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_JSR_2147901275_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.JSR!MTB"
        threat_id = "2147901275"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {45 0f be 0a 8b 11 44 0f be c2 41 8b d1 41 33 d0 41 88 12 49 ff c2 49 83 eb 01 75 e4}  //weight: 1, accuracy: High
        $x_1_2 = "cobalt-strike-master\\x64\\Release\\msedge.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_QE_2147901777_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.QE!MTB"
        threat_id = "2147901777"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff c0 88 04 0c 83 c2 ?? 48 ff c1 48 83 f9 ?? 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c9 4d 8d 49 ?? 48 83 f8 ?? 48 0f 45 c8 0f b6 04 0c 41 30 41 ?? 48 8d 41 ?? 48 83 ea ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_QF_2147901778_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.QF!MTB"
        threat_id = "2147901778"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 04 24 ff c0 89 04 24 8b 44 24 ?? 39 04 24 73}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 0c 24 33 d2 8b c1 b9 ?? ?? ?? ?? 48 f7 f1 48 8b c2 0f b6 44 04 ?? 48 8b 4c 24 ?? 48 8b 54 24 ?? 0f be 0c 11 33 c8 8b c1 8b 0c 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_QG_2147901863_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.QG!MTB"
        threat_id = "2147901863"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 44 24 48 ?? 89 f2 48 89 e9 48 c1 fa ?? 30 54 18 ?? e8 ?? ?? ?? ?? 48 8b 44 24 48 ?? 89 f2 48 89 e9 48 c1 fa ?? 48 c1 fe ?? 30 54 18 ?? e8 ?? ?? ?? ?? 48 8b 44 24 ?? 40 30 74 18 ?? 48 ff c3 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CCHG_2147901878_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CCHG!MTB"
        threat_id = "2147901878"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 20 48 8b 4c 24 78 0f be 04 01 33 44 24 24 8b 4c 24 20 88 44 0c 2c 8b 4c 24 24 e8 ?? ?? ?? ?? 25 ff 00 00 00 89 44 24 24 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_PAC_2147902095_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.PAC!MTB"
        threat_id = "2147902095"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f 1f 00 0f b6 c1 2a c3 32 01 32 c2 88 01 48 03 ce 49 3b c9 72 ed 49 ff c0 48 ff c7 49 ff cb 75 d2 45 33 c9 4c 8b c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_PF_2147902099_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.PF!MTB"
        threat_id = "2147902099"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 8b 03 b8 ?? ?? ?? ?? 41 f7 e1 41 8b c1 c1 ea ?? 41 ff c1 6b d2 ?? 2b c2 8a 4c 18 ?? 41 30 0c 38 48 ff c7 45 3b cb 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_PG_2147902100_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.PG!MTB"
        threat_id = "2147902100"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 04 24 ff c0 89 04 24 8b 44 24 ?? 39 04 24 73 ?? 8b 04 24 0f b6 4c 24 ?? 48 8b 54 24 ?? 0f be 04 02 33 c1 8b 0c 24 48 8b 54 24 ?? 88 04 0a eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_SBN_2147902110_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.SBN!MTB"
        threat_id = "2147902110"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 44 0d ?? 2c 07 88 44 0d 07 48 ff c1 48 83 f9 3c 72}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 44 1d ?? 8b 4d f7 32 c8 88 4c 1d fb 48 ff c3 48 83 fb ?? 72}  //weight: 1, accuracy: Low
        $x_1_3 = "ADVobfuscator@andrivet" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_SAB_2147902113_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.SAB!MTB"
        threat_id = "2147902113"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 14 03 48 ?? ?? 39 f8 89 c2 7c 16 00 83 e2 ?? 8a 54 15 ?? 41}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_HN_2147902121_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.HN!MTB"
        threat_id = "2147902121"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 c2 83 e2 ?? 8a 54 15 ?? 32 14 07 88 14 03 48 ff c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_HR_2147902122_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.HR!MTB"
        threat_id = "2147902122"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 5c 2c 60 88 5c 3c 60 44 88 44 2c 60 0f b6 6c 3c 60 44 01 c5 40 0f b6 ed 0f b6 5c 2c 60 41 30 1c 07}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_HR_2147902122_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.HR!MTB"
        threat_id = "2147902122"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b c1 c7 44 24 40 80 df b2 69 83 e0 0f c7 44 24 44 b4 83 06 ad c7 44 24 48 28 67 9a 31 c7 44 24 4c dc 8b 6e f5 0f 28 44 24 40 66 0f 7f 44 24 60 0f b6 44 04 60 32 84 11 88 7a 01 00 88 44 0c 50 48 ff c1 48 83 f9 0c 72 b6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_HR_2147902122_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.HR!MTB"
        threat_id = "2147902122"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_2 = "\\mfehcs.exe" ascii //weight: 1
        $x_1_3 = "cmd /c taskkill /F /PID" ascii //weight: 1
        $x_1_4 = "\\MyNewDLL\\x64\\Release\\pdh.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_HU_2147902123_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.HU!MTB"
        threat_id = "2147902123"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 89 5a 20 ba ?? ?? ?? ?? 4d 89 99 ?? ?? ?? ?? 83 e1 ?? 49 89 d3 49 d3 e3 44 89 c1 45 09 9c 82 ?? ?? ?? ?? 83 e1 ?? 48 d3 e2 41 09 92 ?? ?? ?? ?? 48 83 c4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_QH_2147902125_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.QH!MTB"
        threat_id = "2147902125"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 98 48 01 c8 0f b6 08 8b 85 ?? ?? ?? ?? 48 98 0f b6 44 05 ?? 31 c8 88 02 83 85 ?? ?? ?? ?? ?? 83 85 ?? ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_XY_2147902135_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.XY!MTB"
        threat_id = "2147902135"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4c 8d 44 24 28 48 89 da b9 68 00 00 00 4c 8d 4b 08 49 29 d8 eb 07 66 90 41 0f b6 0c 10 88 0a 48 83 c2 01 49 39 d1 75 f0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_ZA_2147902181_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.ZA!MTB"
        threat_id = "2147902181"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {41 0f b6 cc 49 89 cc 48 01 d9 0f b6 01 41 01 c1 45 0f b6 d1 4d 89 d1 49 01 da 45 0f b6 1a 44 88 19 41 88 02 02 01 0f b6 c0 0f b6 44 04 ?? 41 30 00 49 83 c0 ?? 49 39 d0 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_ZF_2147902182_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.ZF!MTB"
        threat_id = "2147902182"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 f7 e8 d1 fa 8b c2 c1 e8 1f 03 d0 6b c2 ?? 41 8b ca 2b c8 41 2b cb 41 8d 04 08 48 98 42 8a 8c 30 ?? ?? ?? ?? 43 32 8c 31 ?? ?? ?? ?? 48 8b 85 ?? ?? ?? ?? 41 88 0c 01 44 03 c7 4c 03 cf 44 3b 85 ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_QI_2147902191_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.QI!MTB"
        threat_id = "2147902191"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 8a 04 36 32 84 1f ?? ?? ?? ?? 48 ff c3 41 88 44 35 ?? 83 e3 ?? 48 ff c6 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CCHS_2147902425_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CCHS!MTB"
        threat_id = "2147902425"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 4d f0 48 8d 44 24 68 48 89 44 24 28 45 33 c9 48 89 b4 24 28 01 00 00 45 33 c0 48 8d 35 ?? ?? ?? ?? 33 d2 48 89 74 24 20 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_QM_2147902796_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.QM!MTB"
        threat_id = "2147902796"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 88 04 01 b8 ?? ?? ?? ?? ff 43 ?? 8b 8b ?? ?? ?? ?? 33 8b ?? ?? ?? ?? 2b c1 01 05 ?? ?? ?? ?? b8 ?? ?? ?? ?? 2b 83 ?? ?? ?? ?? 01 83 ?? ?? ?? ?? b8 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? 01 43 ?? 49 81 f9 ?? ?? ?? ?? 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_AC_2147903124_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.AC!MTB"
        threat_id = "2147903124"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 10 0f b6 ca 80 f1 03 88 08 41 f6 c0 01 75 ?? 80 f2 01 88 10 41 ff c0 48 ff c0 45 3b c1 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_KY_2147903317_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.KY!MTB"
        threat_id = "2147903317"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 c2 83 e0 ?? 4c 21 ca 0f b6 44 04 ?? 41 30 04 14 48 8d 42 ?? 48 89 c2 49 0f af d0 48 39 ca 77}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_YAS_2147903375_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.YAS!MTB"
        threat_id = "2147903375"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 43 2c 8b 05 ?? ?? ?? ?? 48 8b 0d ?? ?? ?? ?? 05 aa 12 f4 ff c1 ea 08 01 81 ?? ?? ?? ?? 48 63 4b 6c 48 8b 05 ?? ?? ?? ?? 88 14 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_OPP_2147903481_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.OPP!MTB"
        threat_id = "2147903481"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d1 d1 ea 8d 04 09 33 d0 8d 04 09 41 23 d3 33 d0 8b ca c1 e9 02 8d 04 95 ?? ?? ?? ?? 33 c8 8d 04 95 ?? ?? ?? ?? 81 e1 33 33 33 33 33 c8}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c2 41 33 c0 44 8b c1 41 81 f0 25 ?? ?? ?? 85 c0 44 0f 49 c1 03 d2 49 83 ea 01 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CCHU_2147903508_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CCHU!MTB"
        threat_id = "2147903508"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bd 6c 04 00 00 8b 44 24 70 31 e8 b9 ?? ?? ?? ?? 44 89 f2 44 89 e3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_FO_2147903555_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.FO!MTB"
        threat_id = "2147903555"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d1 c1 e9 ?? 81 e2 ?? ?? ?? ?? c1 e2 ?? 0b d1 0f ca 43 8d 0c 00 8b c2 41 33 c0 44 8b c1 41 81 f0 ?? ?? ?? ?? 85 c0 44 0f 49 c1 03 d2 49 83 ea ?? 75 ?? 49 ff c1 41 8a 01 84 c0 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_FM_2147903556_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.FM!MTB"
        threat_id = "2147903556"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 89 c0 49 f7 e1 4c 89 c1 48 29 d1 48 d1 e9 48 01 ca 48 c1 ea ?? 48 8d 04 92 48 8d 04 80 4c 89 c1 48 29 c1 0f b6 84 0c ?? ?? ?? ?? 48 8d 15 ?? ?? ?? ?? 42 32 04 02 48 8b 94 24 ?? ?? ?? ?? 42 88 04 02 49 83 c0 ?? 4c 39 84 24 ?? ?? ?? ?? 77}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_YAU_2147903581_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.YAU!MTB"
        threat_id = "2147903581"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 2b 06 85 73 31 d2 41 89 d0 42 80 3c 01 00 74 ?? 46 0f b7 04 01 41 89 c1 ff c2 41 c1 c9 08 45 01 c8 44 31 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CCHV_2147903782_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CCHV!MTB"
        threat_id = "2147903782"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 44 24 70 5c 00 00 00 c7 44 24 68 74 00 00 00 c7 44 24 60 6f 00 00 00 c7 44 24 58 6c 00 00 00 c7 44 24 50 73 00 00 00 c7 44 24 48 6c 00 00 00 c7 44 24 40 69 00 00 00 c7 44 24 38 61 00 00 00 c7 44 24 30 6d 00 00 00 c7 44 24 28 5c 00 00 00 c7 44 24 20 2e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CCHW_2147904175_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CCHW!MTB"
        threat_id = "2147904175"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4c 8d 56 01 45 0f b6 59 02 45 31 c3 45 0f b6 41 01 45 31 d8 4c 39 d2 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CCHW_2147904175_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CCHW!MTB"
        threat_id = "2147904175"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 6d 00 31 c0 31 c9 31 d2 31 db eb 0f 41 83 f1 ?? 45 88 4c 18 ff 48 ff c0 4c 89 c1 48 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_AMBG_2147904273_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.AMBG!MTB"
        threat_id = "2147904273"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 89 4c 24 [0-1] 48 89 d9 48 89 c3 48 8d 44 24 [0-2] e8 [0-4] 48 8b 15 [0-4] 48 89 d9 48 89 c3 48 89 d0 [0-2] e8 [0-4] 48 8b 4c 24 [0-1] 48 ff c1 48 39 0d [0-4] 7f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_T_2147904324_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.T!MTB"
        threat_id = "2147904324"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 03 03 45 ?? ff 73 fc 50 8b 43 ?? 03 45 fc 50 ff 95 ?? ?? ?? ?? 0f b7 46 ?? 83 c4 ?? ff 45 e4 83 c3 ?? 39 45 e4}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 45 f4 8a 00 88 45 ff 8a 01 0f be 7d ff 88 45 ?? 0f be c0 2b f8 ff 45 f4 80 7d ff}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_CobaltStrike_JM_2147904373_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.JM!MTB"
        threat_id = "2147904373"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 c8 49 f7 e0 48 c1 ea ?? 48 8d 04 52 48 8d 04 82 48 01 c0 48 89 ca 48 29 c2 0f b6 84 14 ?? ?? ?? ?? 48 8d 15 ?? ?? ?? ?? 32 04 0a 48 8b 94 24 ?? ?? ?? ?? 88 04 0a 48 83 c1 ?? 48 39 8c 24 ?? ?? ?? ?? 77}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_NJ_2147904374_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.NJ!MTB"
        threat_id = "2147904374"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c2 0f af c2 ff c2 01 05 ?? ?? ?? ?? 8b 05 ?? ?? ?? ?? 05 ?? ?? ?? ?? 31 43 ?? 8b 8b ?? ?? ?? ?? 33 4b ?? 8b 05 ?? ?? ?? ?? 81 e9 ?? ?? ?? ?? 0f af c1 89 05 ?? ?? ?? ?? 8b 05 ?? ?? ?? ?? 83 f0 ?? 01 83 ?? ?? ?? ?? 3b 53}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_JZ_2147904515_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.JZ!MTB"
        threat_id = "2147904515"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 8b c1 b9 ?? ?? ?? ?? 48 f7 f1 48 8b c2 0f b6 44 04 ?? 48 8b 4c 24 ?? 48 8b 54 24 ?? 0f be 0c 11 33 c8 8b c1 8b 0c 24 48 8b 54 24 ?? 88 04 0a eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_TYL_2147904972_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.TYL!MTB"
        threat_id = "2147904972"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 33 d2 43 8a 04 02 41 8d 49 ?? 41 30 03 49 8d 42 ?? 45 33 d2 41 83 f9 0b 4c 0f 45 d0 41 8b c1 45 33 c9 ff c3 49 ff c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_JW_2147905007_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.JW!MTB"
        threat_id = "2147905007"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 8a 04 02 41 8d 49 ?? 41 30 03 49 8d 42 ?? 45 33 d2 41 83 f9 ?? 4c 0f 45 d0 41 8b c1 45 33 c9 ff c3 49 ff c3 83 f8 ?? 48 63 c3 44 0f 45 c9 48 3b c2 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_JU_2147905073_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.JU!MTB"
        threat_id = "2147905073"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 04 24 ff c0 89 04 24 48 63 04 24 48 3b 44 24}  //weight: 1, accuracy: High
        $x_1_2 = {0f be 0c 0a 33 c1 48 63 0c 24 48 8b 54 24 ?? 88 04 0a 8b 44 24 ?? ff c0 89 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_JT_2147905074_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.JT!MTB"
        threat_id = "2147905074"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 4c 24 ?? 31 01 48 8b 44 24 ?? 48 83 c0 ?? 48 89 44 24 ?? 48 8b 44 24 ?? 48 83 c0 ?? 48 89 44 24 ?? 48 8b 44 24 ?? 48 3b c6 48 89 44 24 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_MRK_2147905087_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MRK!MTB"
        threat_id = "2147905087"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 49 8b c1 49 f7 f0 4c 8b c2 33 d2 49 8b c1 48 f7 f1 42 0f b6 44 1a ?? 43 0f b6 8c 18 ?? ?? ?? 00 0f af c8 41 02 ca 41 30 0c 39 41 ff c2 45 3b 13 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_JQ_2147905184_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.JQ!MTB"
        threat_id = "2147905184"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b fe 41 8b c8 b8 ?? ?? ?? ?? 33 cf f7 e9 03 d1 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 69 c2 ?? ?? ?? ?? 2b c8 83 f9 ?? 74 ?? ff c7 81 ff ?? ?? ?? ?? 7e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_JI_2147905251_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.JI!MTB"
        threat_id = "2147905251"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 8b 04 03 48 83 c3 ?? 44 0f af 05 ?? ?? ?? ?? 8b 05 ?? ?? ?? ?? ff c8 33 c8 48 8b 05 ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 49 63 c9 41 8b d0 c1 ea ?? 88 14 01 8b 0d ?? ?? ?? ?? 8b 05 ?? ?? ?? ?? ff c1 01 05 ?? ?? ?? ?? 8b 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_KAD_2147905346_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.KAD!MTB"
        threat_id = "2147905346"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 01 d0 0f b6 00 48 8b 4d ?? 48 8b 55 f8 48 01 ca 32 45 ?? 88 02 48 83 45 f8 01 48 8b 45 f8 48 3b 45}  //weight: 1, accuracy: Low
        $x_1_2 = "Debugging detected! Exiting" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CCHZ_2147905467_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CCHZ!MTB"
        threat_id = "2147905467"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 83 ec 60 48 8d 05 a4 86 00 00 48 89 45 f0 48 8d 05 a8 86 00 00 48 89 45 d0 48 8d 05 a8 86 00 00 48 89 45 d8 48 8d 05 a8 86 00 00 48 89 45 c0 48 8d 05 b7 86}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CCHZ_2147905467_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CCHZ!MTB"
        threat_id = "2147905467"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f be 45 4f 8b 55 50 89 55 48 88 45 47 0f be 45 47 33 45 48 69 c0 ?? ?? ?? ?? 89 45 50 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 45 58 48 8d 50 01 48 89 55 58 0f b6 00 88 45 4f 80 7d 4f 00 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_YAV_2147905832_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.YAV!MTB"
        threat_id = "2147905832"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 0f b6 14 09 48 8d 49 01 80 ea 0c 41 ff c0 88 51 ff 41 83 f8 0c 72 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_APP_2147906097_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.APP!MTB"
        threat_id = "2147906097"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 c8 44 02 d9 44 02 df 41 0f b6 cb 41 0f b6 44 8e 08 41 30 47 01 41 8b 44 8e ?? 41 31 44 96 ?? 41 8b 44 ae 08 41 8d 0c 00 43 31 4c 96 ?? 40 fe c5 40 0f b6 ed}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_YAW_2147906186_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.YAW!MTB"
        threat_id = "2147906186"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 45 c8 b8 ?? ?? ?? ?? 44 0f b6 c1 48 8b 4e 10 41 2b e8 41 2b ed 83 c5 ?? f7 ed c1 fa 03 8b c2 c1 e8 1f 03 d0 6b c2 1a 48 8b 56 18 2b e8 41 02 e8 48 3b ca}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_DA_2147906414_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.DA!MTB"
        threat_id = "2147906414"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 01 d0 44 0f b6 08 48 8b 8d ?? ?? ?? ?? 48 89 c8 48 c1 e8 02 48 ba ?? ?? ?? ?? ?? ?? ?? ?? 48 f7 e2 48 89 d0 48 d1 e8 48 89 c2 48 8d 04 95 00 00 00 00 48 89 c2 48 8d 04 d5 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {48 29 d0 48 29 c1 48 89 c8 0f b6 84 05 ?? ?? ?? ?? 44 31 c8 41 88 00 48 83 85 ?? ?? ?? ?? ?? 48 8b 85 ?? ?? ?? ?? 48 39 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_AMMF_2147906612_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.AMMF!MTB"
        threat_id = "2147906612"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 89 f1 83 e1 0f 0f b6 0c 01 42 32 0c 33 42 88 0c 37 49 ff c6 48 8b 5d ?? 48 8b 4d ?? 48 29 d9 49 39 ce}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_AMMF_2147906612_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.AMMF!MTB"
        threat_id = "2147906612"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b8 ab aa aa 2a 4d 8d 52 01 41 f7 e8 d1 fa 8b c2 c1 e8 1f 03 d0 41 8b c0 41 ff c0 8d 0c 52 c1 e1 02 2b c1 48 98 42 0f b6 04 18 41 30 42 ff 45 3b c1 7c}  //weight: 1, accuracy: High
        $x_1_2 = {30 14 0b 02 14 0b e2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_CobaltStrike_PADM_2147907028_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.PADM!MTB"
        threat_id = "2147907028"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "kapitalbankaz.azurewebsites.net/api/getit" ascii //weight: 1
        $x_1_2 = "InternetExplorer.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_TJ_2147907119_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.TJ!MTB"
        threat_id = "2147907119"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 c8 31 d2 49 f7 f6 48 39 cf 74 1f 48 6b c0 ?? 48 01 f0 48 8d 59 ?? 8a 14 08 32 54 0d ?? 4c 89 f9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_TK_2147907239_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.TK!MTB"
        threat_id = "2147907239"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 0f b6 0a 88 08 48 ff c0 b9 ?? ?? ?? ?? 66 d1 eb 4c 03 d1 66 85 dd 0f 85 ?? ?? ?? ?? 4c 3b d7 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CCIB_2147907260_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CCIB!MTB"
        threat_id = "2147907260"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 63 44 24 20 48 8d 54 24 40 48 8b 4c 24 70 48 8b 0c c1 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_YAX_2147907267_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.YAX!MTB"
        threat_id = "2147907267"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 c1 e0 05 48 8d 04 91 4c 29 c0 0f b6 84 04 ?? ?? ?? ?? 48 8d 15 55 5e 08 00 32 04 0a 48 8b 94 24 c8 05 00 00 88 04 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_YAY_2147907268_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.YAY!MTB"
        threat_id = "2147907268"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 74 74 70 3a 2f 2f 31 34 39 2e 32 38 2e 32 32 32 2e 32 34 34 3a 38 30 30 30 2f [0-10] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_2 = "Download" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_YAZ_2147907272_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.YAZ!MTB"
        threat_id = "2147907272"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {59 49 08 c7 c0 00 00 98 48 83 c1 ?? 00 4a 8d 14 01 81 32 dd cc 00 bb aa 44 89 c0 49 83 e8 00 04 48 8d 52 fc 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_RSK_2147907399_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.RSK!MTB"
        threat_id = "2147907399"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {65 48 8b 04 25 60 00 00 00 48 89 45 48 48 8b 45 48 48 8b 40 18 48 89 45 68 48 8b 45 68 48 83 c0 20 48 89 85 88 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_TM_2147907431_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.TM!MTB"
        threat_id = "2147907431"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b cd f7 ed d1 fa 8b c2 c1 e8 ?? 03 d0 8d 04 92 2b c8 48 63 c1 42 8a 84 28 ?? ?? ?? ?? 42 32 44 37 ?? 41 88 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_TN_2147907444_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.TN!MTB"
        threat_id = "2147907444"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 0c 24 33 d2 8b c1 b9 ?? ?? ?? ?? 48 f7 f1 48 8b c2 0f b6 44 04 ?? 48 8b 4c 24 ?? 48 8b 54 24 ?? 0f be 0c 11 33 c8 8b c1 8b 0c 24 48 8b 54 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CM_2147907597_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CM!MTB"
        threat_id = "2147907597"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {29 c3 0f af d8 f6 c3 01 0f 94 c0 08 c1 89 d3 30 cb 30 c2 30 c1 80 f2 01 08 da 38 d1 0f 85}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_TP_2147907689_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.TP!MTB"
        threat_id = "2147907689"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 c8 31 d2 49 f7 f6 48 39 cb 74 1f 48 6b c0 ?? 48 01 f0 48 8d 79 ?? 8a 14 08 32 54 0d ?? 4c 89 f9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_TQ_2147907690_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.TQ!MTB"
        threat_id = "2147907690"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 44 14 ?? 8d 48 ?? 80 f9 ?? 77 ?? 2c ?? 88 44 14 ?? 48 ff c2 48 3b d6}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c8 c1 e9 ?? 33 c8 69 c9 ?? ?? ?? ?? 33 e9 49 83 e8 ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_TR_2147907691_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.TR!MTB"
        threat_id = "2147907691"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 f0 83 e0 ?? 41 8a 04 04 32 44 35 ?? 88 04 33 48 ff c6 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_YBA_2147907927_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.YBA!MTB"
        threat_id = "2147907927"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 01 d0 48 29 c1 48 89 ca 0f b6 84 15 ?? ?? ?? ?? 44 31 c8 41 88 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_PADS_2147908264_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.PADS!MTB"
        threat_id = "2147908264"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Beginning sandbox evasion routine" ascii //weight: 1
        $x_1_2 = "This is probably a sandbox, or someone attached a debugger and stepped over the loop" ascii //weight: 1
        $x_1_3 = "Shellcode decryption complete." ascii //weight: 1
        $x_1_4 = "Tasked to write shellcode to allocated memory in the target process" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_RCB_2147908435_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.RCB!MTB"
        threat_id = "2147908435"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "f574d29994a3adc68dcbd2a39596331713957734.bin.packed.dll" ascii //weight: 1
        $x_5_2 = {48 89 d0 48 83 f0 ff 48 09 c8 49 89 c8 49 83 f0 ff 49 21 d0 49 89 c9 49 21 d1 49 83 f1 ff 48 09 d1 4c 01 c0 4c 29 c8 48 01 c8}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_YBC_2147908723_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.YBC!MTB"
        threat_id = "2147908723"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 f7 f1 48 8b c2 0f b6 44 04 ?? 48 8b 4c 24 48 48 8b 54 24 60 0f b6 0c 11 33 c8 8b c1 48 63 4c 24 20 48 8b 54 24 48 88 04 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_YBD_2147908724_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.YBD!MTB"
        threat_id = "2147908724"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b c2 48 8d 49 01 83 e0 03 48 ff c2 0f b6 84 05 c8 01 00 00 32 84 39 a5 41 00 00 88 44 0c 27 49 83 e8 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_PQ_2147909128_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.PQ!MTB"
        threat_id = "2147909128"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b cb 44 38 6d ?? 74 ?? 45 85 c9 7e ?? 48 8d 95 ?? ?? ?? ?? 48 2b d3 45 8b c1 8a 04 0a 30 01 48 ff c1 49 83 e8 ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_PQ_2147909128_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.PQ!MTB"
        threat_id = "2147909128"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c8 83 f1 28 0f af c8 41 8b d1 45 8b c1 c1 ea 18 41 c1 e8 10 89 8b [0-4] 48 63 8b [0-4] 8b 83 [0-4] 33 83 [0-4] 83 e8 12 01 43 [0-4] 8b 43 [0-4] 29 83 [0-4] 48 8b 83 [0-4] 88 14 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_HNF_2147909130_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.HNF!MTB"
        threat_id = "2147909130"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 04 01 8b 4c 24 20 83 e1 05 48 63 c9 48 8d 15 ?? ?? ?? ?? 0f b6 0c 0a 33 c1 48 63 4c 24 20 48 8d 15 ?? ?? ?? ?? 88 04 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CCID_2147909160_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CCID!MTB"
        threat_id = "2147909160"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f be 04 01 83 f0 08 83 f0 58 48 63 4c 24 ?? 48 8b 54 24 ?? 88 04 0a eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_FUJ_2147909188_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.FUJ!MTB"
        threat_id = "2147909188"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 44 24 38 48 89 44 24 08 33 d2 48 8b 04 24 48 8b 4c 24 08 48 f7 f1 48 8b c2 48 8b 4c 24 30 0f b7 04 41 48 8b 4c 24 20 48 8b 14 24 0f b7 0c 51 33 c8 8b c1 48 8b 4c 24 20 48 8b 14 24 66 89 04 51}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_RTG_2147909189_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.RTG!MTB"
        threat_id = "2147909189"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 f7 e1 48 c1 ea 04 48 6b c2 11 49 8b d1 48 2b d0 42 8a 04 02 42 30 04 09 49 ff c1 4d 3b ca 76 d5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_FW_2147909571_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.FW!MTB"
        threat_id = "2147909571"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c2 2b 83 ?? ?? ?? ?? 89 4b ?? 83 f0 ?? 41 0f af c1 89 43 ?? 8b 4b ?? 2b ca 81 c1 ?? ?? ?? ?? 31 4b ?? 49 81 fb ?? ?? ?? ?? 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_FI_2147909572_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.FI!MTB"
        threat_id = "2147909572"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 08 48 8b 45 ?? ba ?? ?? ?? ?? 48 f7 75 ?? 48 8b 45 ?? 48 01 d0 0f b6 10 4c 8b 45 ?? 48 8b 45 ?? 4c 01 c0 31 ca 88 10 48 83 45 ?? ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_HND_2147909701_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.HND!MTB"
        threat_id = "2147909701"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 57 69 6e 69 6e 65 74 2e [0-9] c7 84 24 ?? ?? 00 00 64 6c 6c 00 [0-8] ff d7 [0-9] b8 65 74 4f 70 65 6e 41 00 [0-10] 48 b8 49 6e 74 65 72 6e 65 74 [0-21] ff d6}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 c1 0f b6 4c 04 ?? 42 30 8c 04 ?? ?? 00 00 49 ff c0 49 81 f8 ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_CobaltStrike_CCIF_2147909748_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CCIF!MTB"
        threat_id = "2147909748"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 8a 44 35 ?? 41 32 84 1f ?? ?? ?? ?? 48 ff c3 83 e3 0f 88 44 37 ?? 48 ff c6 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CCIG_2147909749_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CCIG!MTB"
        threat_id = "2147909749"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 00 00 73 c6 85 ?? 03 00 00 25 c6 85 ?? 03 00 00 72 c6 85 ?? 03 00 00 29 c6 85 ?? 03 00 00 54 c6 85 ?? 03 00 00 4f c6 85 ?? 03 00 00 52 c6 85 ?? 03 00 00 33 c6 85 ?? 03 00 00 63 c6 85 ?? 03 00 00 31 c6 85 ?? 03 00 00 4c c6 85 ?? 03 00 00 73 c6 85 ?? 03 00 00 4e c6 85 ?? 03 00 00 52 c6 85 ?? 03 00 00 38 c6 85 ?? 03 00 00 30 c6 85 ?? 03 00 00 5a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_FJ_2147909800_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.FJ!MTB"
        threat_id = "2147909800"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 88 04 01 48 8b 05 ?? ?? ?? ?? ff 40 ?? 8b 4b ?? 8b 93 ?? ?? ?? ?? 8b 43 ?? 33 05 ?? ?? ?? ?? ff c8 09 83 ?? ?? ?? ?? 8d 82 ?? ?? ?? ?? 33 53 ?? 03 c1 31 43 ?? 81 ea ?? ?? ?? ?? 2b 4b ?? ff c1 89 4b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_WS_2147909975_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.WS!MTB"
        threat_id = "2147909975"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {65 48 8b 04 25 60 00 00 00 48 85 c0 0f 84 91 00 00 00 83 b8 18 01 00 00 0a 0f 85 84 00 00 00 48 8b 40 18 48 8b 48 20 48 8b 01 4c 8b 50 20}  //weight: 1, accuracy: High
        $x_1_2 = "Press <Enter> To Execute The Payload ..." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_PADU_2147910096_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.PADU!MTB"
        threat_id = "2147910096"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 45 fc 00 00 00 00 8b 45 f8 48 63 d0 48 8b 45 10 48 01 d0 44 0f b6 00 8b 45 fc 48 63 d0 48 8b 45 20 48 01 d0 0f b6 08 8b 45 f8 48 63 d0 48 8b 45 10 48 01 d0 44 89 c2 31 ca 88 10 83 45 fc 01 83 45 f8 01 8b 45 f8 48 98 48 3b 45 18 72 9e}  //weight: 1, accuracy: High
        $x_1_2 = {ba e1 e8 c1 1a 48 89 c1 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_KN_2147910135_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.KN!MTB"
        threat_id = "2147910135"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 0f b6 cb 41 0f b6 44 8e ?? 41 30 47 ?? 41 8b 44 8e ?? 41 31 44 96 ?? 41 8b 44 ae ?? 41 8d 0c 00 43 31 4c 96 ?? 40 fe c5 40 0f b6 ed 41 8b 7c ae}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_YYY_2147910219_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.YYY!MTB"
        threat_id = "2147910219"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4d 01 d1 49 bb db 28 b4 a0 d1 7e 03 e7 4d 31 cb 48 89 c7 4c 89 c8 49 89 d4 49 f7 e3 4d 89 88 ?? ?? ?? ?? 44 8b 05 44 75 30 00 48 31 d0 ?? 45 85 c0 0f 84}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_ENG_2147910324_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.ENG!MTB"
        threat_id = "2147910324"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "T2UEpgoBFw6HXoZ87FKIgOqfrPyZeaVSk4DIgNm9VRPw7TSVESbQzZo0rpAGJyh5TtY" ascii //weight: 1
        $x_1_2 = "/CPNGXa3g1gm8hD3zsdW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_TBC_2147910414_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.TBC!MTB"
        threat_id = "2147910414"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 98 48 8d 0d 97 83 11 00 0f b6 04 01 88 45 64 48 8b 85 90 01 00 00 0f be 00 0f b6 4d 64 33 c1 88 85 84 00 00 00 48 8b 85 90 01 00 00 0f b6 8d 84 00 00 00 88 08 48 8b 85 90 01 00 00 48 ff c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_AZX_2147910593_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.AZX!MTB"
        threat_id = "2147910593"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 c2 48 8b 4c 24 68 83 e2 ?? 41 8a 54 15 00 41 32 14 04 88 14 01 48 ff c0 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_IRH_2147910696_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.IRH!MTB"
        threat_id = "2147910696"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 89 cf 48 89 d9 48 89 c3 48 8d 44 24 48 e8 ba 80 fa ff 48 8d 44 24 48 31 db 31 c9 48 89 cf}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_FN_2147910786_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.FN!MTB"
        threat_id = "2147910786"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 00 31 c3 89 da 8b 85 d8 b0 04 00 48 98 88 54 05 70 83 85 dc b0 04 00 01 83 85 d8 b0 04 00 01 8b 85 d8 b0 04 00 48 98}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_FN_2147910786_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.FN!MTB"
        threat_id = "2147910786"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 01 48 8d 49 ?? ff c0 3d ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
        $x_1_2 = {41 0f b6 14 18 41 8d 04 12 44 0f b6 d0 42 0f b6 04 11 41 88 04 18 42 88 14 11 41 0f b6 0c 18 48 03 ca 0f b6 c1 0f b6 4c 04 ?? 41 30 49 ff 49 83 eb ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CCII_2147910873_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CCII!MTB"
        threat_id = "2147910873"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 f9 8b c2 48 98 48 8b 8c 24 ?? ?? ?? ?? 0f be 04 01 48 8b 8c 24 ?? ?? ?? ?? 48 8b 94 24 ?? ?? ?? ?? 0f b6 0c 11 33 c8 8b c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_YBE_2147910943_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.YBE!MTB"
        threat_id = "2147910943"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 d0 48 c1 e8 ?? 48 ?? ?? ?? 48 ?? ?? ?? 48 01 c0 48 89 ce 48 29 c6 0f b6 84 34 60 06 00 00 48 8d 15 ?? ?? ?? ?? 32 04 0a 48 8b 94 24 ?? ?? ?? ?? 88 04 0a 48 83 c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_YBF_2147910944_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.YBF!MTB"
        threat_id = "2147910944"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8d 04 52 48 c1 e0 03 48 29 d0 4c 89 c6 48 29 c6 0f b6 84 34 60 06 00 00 48 8d 15 ?? ?? ?? ?? 42 32 04 02 48 8b 94 24 88 06 00 00 42 88 04 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CCIJ_2147910977_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CCIJ!MTB"
        threat_id = "2147910977"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 f0 83 e0 ?? 45 8a 7c 05 ?? ff ?? 45 31 fe 44 88 34 33 48 ff c6 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_IC_2147911115_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.IC!MTB"
        threat_id = "2147911115"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {42 8a 0c 0a 41 88 09 49 ff c1 49 83 e8 ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {49 8b c2 49 f7 f1 42 8a 0c 02 43 30 0c 1a 49 ff c2 4c 3b d3 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CMD_2147911303_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CMD!MTB"
        threat_id = "2147911303"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 c1 48 8b 95 e0 4f 00 00 8b 85 d4 4f 00 00 48 98 88 0c 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_ES_2147911534_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.ES!MTB"
        threat_id = "2147911534"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4c 89 c0 49 f7 e1 4c 89 c1 48 29 d1 48 d1 e9 48 01 ca 48 c1 ea 04 48 8d 04 92 48 8d 04 82 4c 89 c6 48 29 c6 0f b6 84 34 60 06 00 00 48 8d 15 01 3d 20 00 42 32 04 02 48 8b 94 24 88 06 00 00 42 88 04 02 49 83 c0 01 4c 39 84 24 80 06 00 00 77 af ff 94 24 88 06 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_IG_2147911678_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.IG!MTB"
        threat_id = "2147911678"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 c3 39 f7 7e ?? 48 89 f0 83 e0 ?? 45 8a 2c 04 44 32 6c 35 ?? ff 15 ?? ?? ?? ?? 44 88 2c 33 48 ff c6 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CCIK_2147912065_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CCIK!MTB"
        threat_id = "2147912065"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 03 d1 48 8b ca 48 0f be 09 48 33 c8 48 8b c1 48 8b 8d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_ACT_2147912071_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.ACT!MTB"
        threat_id = "2147912071"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 85 a3 fc 03 00 42 c6 85 a4 fc 03 00 42 c6 85 a5 fc 03 00 42 c6 85 a6 fc 03 00 42 c6 85 a7 fc 03 00 42 c6 85 a8 fc 03 00 42 c6 85 a9 fc 03 00 42 c6 85 aa fc 03 00 42 c6 85 ab fc 03 00 42 c6 85 ac fc 03 00 42 c6 85 ad fc 03 00 42 c6 85 ae fc 03 00 42 c6 85 af fc 03 00 42 c6 85 b0 fc 03 00 42 c6 85 b1 fc 03 00 42 c6 85 b2 fc 03 00 42 c6 85 b3 fc 03 00 42}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_ACT_2147912071_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.ACT!MTB"
        threat_id = "2147912071"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 c2 48 8b 45 10 48 01 d0 0f b7 00 66 89 45 f6 0f b7 45 f6 8b 55 f8 c1 ca 08 01 d0 31 45 f8 8b 45 fc 48 8b 55 10 48 01 d0 0f b6 00 84 c0}  //weight: 1, accuracy: High
        $x_1_2 = {c6 85 35 02 00 00 74 c6 85 36 02 00 00 63 c6 85 37 02 00 00 65 c6 85 38 02 00 00 74 c6 85 39 02 00 00 6f c6 85 3a 02 00 00 72 c6 85 3b 02 00 00 50 c6 85 3c 02 00 00 6c c6 85 3d 02 00 00 61 c6 85 3e 02 00 00 75 c6 85 3f 02 00 00 74 c6 85 40 02 00 00 72 c6 85 41 02 00 00 69 c6 85 42 02 00 00 56}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_OFF_2147912169_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.OFF!MTB"
        threat_id = "2147912169"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 d2 4d 8d 49 01 41 8b c0 41 ff c0 41 f7 f2 0f b6 54 14 48 41 30 51 ff 44 3b c6 72 e3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CCIL_2147912201_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CCIL!MTB"
        threat_id = "2147912201"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 b9 40 00 00 00 41 b8 00 10 00 00 48 89 d3 48 89 ce 31 c9 ff 15 ?? ?? ?? ?? 49 89 d8 48 89 f2 48 89 c1 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_OFK_2147912251_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.OFK!MTB"
        threat_id = "2147912251"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 c8 44 02 d9 44 02 df 41 0f b6 cb 49 83 c6 05 41 0f b6 44 8d 08 41 30 46 fe 41 8b 44 8d 08 41 31 44 95 ?? 41 8b 44 ad 08 41 8d 0c 00 43 31 4c 95 08 49 ff cf 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_KS_2147912539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.KS!MTB"
        threat_id = "2147912539"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {65 48 8b 04 25 60 00 00 00 48 89 45 48 48 8b 45 48 48 8b 40 18 48 89 45 68 48 8b 45 68 48 8b 40 20 48 89 85 88 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_IO_2147912606_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.IO!MTB"
        threat_id = "2147912606"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff c0 89 85 ?? ?? ?? ?? 8b 45 ?? 39 85 ?? ?? ?? ?? 0f 8d}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b c1 48 8b 8d ?? ?? ?? ?? 48 f7 f1 48 8b c2 48 8b 8d ?? ?? ?? ?? 0f be 04 01 8b 8d ?? ?? ?? ?? 33 c8 8b c1 48 63 8d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_PJ_2147912831_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.PJ!MTB"
        threat_id = "2147912831"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c1 c1 f9 ?? 29 ca 6b ca ?? 29 c8 89 c2 89 d0 83 c0 ?? 44 89 c1 31 c1 48 8b 55 ?? 8b 45 ?? 48 98 88 0c 02 83 45 ?? ?? 83 7d ?? ?? 7e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_PK_2147912832_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.PK!MTB"
        threat_id = "2147912832"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 63 c0 46 8a 04 02 41 b9 ?? ?? ?? ?? 31 d2 41 f7 f1 8b 44 24 ?? 41 89 d1 48 8b 54 24 ?? 4d 63 c9 46 32 04 0a 48 63 d0 44 88 04 11}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_PL_2147912961_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.PL!MTB"
        threat_id = "2147912961"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 0f 45 d1 48 8b 4d ?? 8a 44 15 ?? 30 04 0f 48 8d 4a ?? 41 ff c0 48 ff c7 49 63 c0 49 3b c1 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_NU_2147913014_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.NU!MTB"
        threat_id = "2147913014"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 44 24 08 48 3b 44 24 20 0f 83 47 00 00 00 48 8b 44 24 18 48 89 04 24 48 8b 44 24 08 31 c9 89 ca 48 f7 74 24 10 48 8b 04 24 44 0f b6 04 10 48 8b 44 24 28 48 8b 4c 24 08 0f b6 14 08 44 31 c2 88 14 08 48 8b 44 24 08 48 83 c0 01 48 89 44 24 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_PN_2147913076_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.PN!MTB"
        threat_id = "2147913076"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 04 24 48 89 44 24 ?? 8b 0c 24 33 d2 8b c1 b9 ?? ?? ?? ?? 48 f7 f1 48 8b c2 0f b6 44 04 ?? 48 8b 4c 24 ?? 48 8b 54 24 ?? 0f be 0c 11 33 c8 8b c1 8b 0c 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_YR_2147913094_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.YR!MTB"
        threat_id = "2147913094"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {65 48 8b 04 25 30 00 00 00 48 8b 40 60 48 8b 40 18 48 8b 40 20 4c 8b 18 4d 8d 53 f0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_ACB_2147913163_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.ACB!MTB"
        threat_id = "2147913163"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {99 48 8d 5b 01 f7 fd fe c2 32 54 1e ff 41 32 d6 88 53 ff 48 83 ef 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_ACB_2147913163_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.ACB!MTB"
        threat_id = "2147913163"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 89 c9 8d 04 1a 41 32 44 10 10 49 c1 f9 08 44 31 c8 49 89 c9 48 c1 f9 18 49 c1 f9 10 44 31 c8 31 c8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_ACB_2147913163_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.ACB!MTB"
        threat_id = "2147913163"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 85 00 03 00 00 79 c6 85 01 03 00 00 72 c6 85 02 03 00 00 6f c6 85 03 03 00 00 6d c6 85 04 03 00 00 65 c6 85 05 03 00 00 4d c6 85 06 03 00 00 73 c6 85 07 03 00 00 73 c6 85 08 03 00 00 65 c6 85 09 03 00 00 63 c6 85 0a 03 00 00 6f c6 85 0b 03 00 00 72 c6 85 0c 03 00 00 50 c6 85 0d 03 00 00 65 c6 85 0e 03 00 00 74 c6 85 0f 03 00 00 69 c6 85 10 03 00 00 72 c6 85 11 03 00 00 57}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CCIQ_2147913214_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CCIQ!MTB"
        threat_id = "2147913214"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 8b cd 48 8b cf 80 31 ?? 44 03 ce 48 03 ce 41 81 f9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CCIZ_2147913231_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CCIZ!MTB"
        threat_id = "2147913231"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "OTA5MDkwZmM0ODgzZTRmMGU4YzgwMDAwMDA0MTUxNDE1MDUyNT" ascii //weight: 1
        $x_1_2 = "E1NjQ4MzFkMjY1NDg4YjUyNjA0ODhiNTIxODQ4OGI1MjIwNDg4" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_FL_2147913337_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.FL!MTB"
        threat_id = "2147913337"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 c8 31 d2 49 f7 f2 41 0f b6 04 13 41 30 04 09 48 ff c1 49 39 c8 74 ?? 48 89 c8 4c 09 d0 48 c1 e8 ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_ID_2147913338_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.ID!MTB"
        threat_id = "2147913338"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 08 48 8b 45 ?? 41 89 c0 8b 45 ?? 48 98 48 8b 55 ?? 48 01 d0 44 31 c1 89 ca 88 10 83 45 ?? ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_IH_2147913339_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.IH!MTB"
        threat_id = "2147913339"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 0f b6 c0 ff c2 2a 01 48 8d 49 ?? 41 32 c1 88 41 ?? 81 fa ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_IQ_2147913343_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.IQ!MTB"
        threat_id = "2147913343"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff c0 89 85 ?? ?? ?? ?? 8b 45 ?? 39 85 ?? ?? ?? ?? 7d ?? 8b 85 ?? ?? ?? ?? 83 c0 ?? 99 f7 7d ?? 8b c2}  //weight: 1, accuracy: Low
        $x_1_2 = {0f be 04 01 48 63 8d ?? ?? ?? ?? 48 8b 95 ?? ?? ?? ?? 0f be 0c 0a 33 c1 48 63 8d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_RP_2147913390_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.RP!MTB"
        threat_id = "2147913390"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f6 d1 44 8d 04 09 80 c9 ?? 00 c2 44 00 c2 28 ca 80 c2 01 88 15 ?? ?? ?? 00 8a 05 ?? ?? ?? 00 89 c1 89 c2 80 e2 ?? 00 c2 34 ?? f6 d1 44 8d 04 09 80 c9 ?? 00 c2 44 00 c2 28 ca 80 c2 01 88 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_OSA_2147913506_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.OSA!MTB"
        threat_id = "2147913506"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 88 57 fc 88 54 24 72 0f b6 54 24 73 41 32 51 0d 41 88 57 fd 88 54 24 73 0f b6 54 24 74 41 32 51 0e 41 88 57 fe 45 32 71 0f 4c 39 8c 24 ?? ?? ?? ?? 88 54 24 50 45 88 77 ff 0f 84}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_ZX_2147913668_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.ZX!MTB"
        threat_id = "2147913668"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f af c1 89 42 70 48 8b 15 d4 f2 02 00 8b 05 ea f3 02 00 05 3f 25 ee ff 8b 8a 2c 01 00 00 33 0d 05 f3 02 00 03 c8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_YBL_2147913680_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.YBL!MTB"
        threat_id = "2147913680"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 44 14 58 41 32 c7 88 04 0a 48 ff c2 84 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_YBL_2147913680_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.YBL!MTB"
        threat_id = "2147913680"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 d1 8b ca 81 c1 7c db 03 00 48 8b 94 24 98 00 00 00 8b 44 02 18 33 c1 b9 04 00 00 00 48 6b c9 01 48 8b 94 24 98 00 00 00 89 44 0a 18 8b 44 24 38 c1 e8 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_YBM_2147913681_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.YBM!MTB"
        threat_id = "2147913681"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 33 c6 01 05 59 f7 02 00 44 0f af 41 78 8b 05 ae f7 02 00 2b 41 40 01 81 a4 00 00 00 48 8b 05 ?? ?? ?? ?? 41 8b d0 c1 ea 18 48 63 88 a8 00 00 00 48 8b 05 ?? ?? ?? ?? 88 14 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_PS_2147913698_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.PS!MTB"
        threat_id = "2147913698"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b c1 0f b6 00 83 f0 ?? 48 63 4c 24 ?? 48 6b c9 ?? 48 8d 54 24 ?? 48 03 d1 48 8b ca 88 01 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_TVV_2147913779_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.TVV!MTB"
        threat_id = "2147913779"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 31 c2 88 14 0b 48 ff c1 48 89 d8 48 89 fa 48 39 ca 7e 34}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_PU_2147914039_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.PU!MTB"
        threat_id = "2147914039"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 8b cd 48 83 f8 ?? 48 0f 45 c8 0f b6 44 0c ?? 30 02 48 8d 41 ?? 48 8d 52 ?? 49 83 e8 ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_PV_2147914040_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.PV!MTB"
        threat_id = "2147914040"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b c6 41 ff c1 4d 8d 52 ?? 48 f7 e1 48 c1 ea ?? 48 8d 04 92 48 c1 e0 ?? 48 2b c8 48 03 cb 0f b6 44 0c ?? 43 32 44 13 ?? 41 88 42 ?? 41 81 f9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_PV_2147914040_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.PV!MTB"
        threat_id = "2147914040"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 04 24 ff c0 89 04 24 48 63 04 24 48 3d [0-4] 73 ?? 48 63 04 ?? 48 8d 0d ?? ?? ?? ?? 0f b6 04 01 03 44 24 ?? 33 44 24 ?? 48 63 0c 24 48 8d 15 ?? ?? ?? ?? 88 04 0a eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_FA_2147914076_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.FA!MTB"
        threat_id = "2147914076"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "The resource owner" ascii //weight: 1
        $x_1_2 = "Decrypted %d... (%d %%) i = %d; full_length = %d" ascii //weight: 1
        $x_1_3 = "Decrypted %d...ok!" ascii //weight: 1
        $x_1_4 = "Old protect%d " ascii //weight: 1
        $x_1_5 = "[=] Star" ascii //weight: 1
        $x_1_6 = "*,d:/th/ds/ext/aad" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_EMP_2147914334_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.EMP!MTB"
        threat_id = "2147914334"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 c0 89 44 24 2c 8b 54 24 2c 89 d0 c1 e8 1f 01 d0 d1 f8 89 44 24 2c 8b 44 24 2c 35 aa aa 00 00 89 44 24 2c 8b 44 24 2c 0f b7 c0 89 44 24 2c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_PX_2147914506_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.PX!MTB"
        threat_id = "2147914506"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 04 24 ff c0 89 04 24 48 63 04 24 48 3b 44 24 ?? 73 ?? 48 63 04 24 0f b6 4c 24 ?? 48 8b 54 24 ?? 0f b6 04 02 33 c1 48 63 0c 24 48 8b 54 24 ?? 88 04 0a eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CCJA_2147914536_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CCJA!MTB"
        threat_id = "2147914536"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b ca f7 d2 c1 e9 18 33 c1 23 c2 41 ff c9 66 41 39 30 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CCJB_2147914804_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CCJB!MTB"
        threat_id = "2147914804"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 8d 6c 24 4c 48 89 cd 41 89 d4 b9 40 00 00 00 ba 0b 00 00 00 48 89 ef ff 15 ?? ?? ?? ?? 44 8b 44 24 3c c7 44 24 28 00 00 00 00 48 8d 15 ?? ?? ?? ?? 48 89 c3 c7 44 24 20 00 00 00 00 48 89 c1 48 89 de 45 0f be c8 45 0f b6 c4 e8 ?? ?? ?? ?? 4d 89 e9 48 89 e9 ba 0b 00 00 00 4c 8b 25 ?? ?? ?? ?? 41 b8 40 00 00 00 41}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_ACO_2147915211_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.ACO!MTB"
        threat_id = "2147915211"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {88 14 01 33 d2 8b 44 24 28 f7 74 24 54 8b c2 8b c0 48 63 4c 24 28 48 8b 54 24 58 0f b6 44 04 40 88 04 0a}  //weight: 2, accuracy: High
        $x_3_2 = {b8 41 00 00 00 66 89 44 24 48 b8 33 00 00 00 66 89 44 24 4a b8 43 00 00 00 66 89 44 24 4c b8 38 00 00 00 66 89 44 24 4e b8 32 00 00 00 66 89 44 24 50 b8 31 00 00 00 66 89 44 24 52 b8 37 00 00 00 66 89 44 24 54 b8 30 00 00 00 66 89 44 24 56 33 c0 66 89 44 24 58 c7 44 24 60 08 00 00 00 ff 15}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_ACO_2147915211_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.ACO!MTB"
        threat_id = "2147915211"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 c7 85 40 06 00 00 6c 00 66 c7 85 42 06 00 00 6c 00 66 c7 85 44 06 00 00 64 00 66 c7 85 46 06 00 00 2e 00 66 c7 85 48 06 00 00 32 00 66 c7 85 4a 06 00 00 33 00 66 c7 85 4c 06 00 00 6c 00 66 c7 85 4e 06 00 00 65 00 66 c7 85 50 06 00 00 6e 00 66 c7 85 52 06 00 00 72 00 66 c7 85 54 06 00 00 65 00 66 c7 85 56 06 00 00 4b 00}  //weight: 1, accuracy: High
        $x_1_2 = {66 c7 85 20 06 00 00 6c 00 66 c7 85 22 06 00 00 6c 00 66 c7 85 24 06 00 00 64 00 66 c7 85 26 06 00 00 2e 00 66 c7 85 28 06 00 00 6c 00 66 c7 85 2a 06 00 00 6c 00 66 c7 85 2c 06 00 00 64 00 66 c7 85 2e 06 00 00 74 00 66 c7 85 30 06 00 00 6e 00}  //weight: 1, accuracy: High
        $x_1_3 = {89 c2 48 8b 45 10 48 01 d0 0f b7 00 66 89 45 f6 0f b7 55 f6 8b 45 f8 c1 c8 08 01 d0 31 45 f8 8b 55 fc 48 8b 45 10 48 01 d0 0f b6 00 84 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_ACR_2147915224_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.ACR!MTB"
        threat_id = "2147915224"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 85 f4 06 00 00 63 c6 85 f5 06 00 00 6f c6 85 f6 06 00 00 6c c6 85 f7 06 00 00 6c c6 85 f8 06 00 00 41 c6 85 f9 06 00 00 6c c6 85 fa 06 00 00 61 c6 85 fb 06 00 00 75 c6 85 fc 06 00 00 74 c6 85 fd 06 00 00 72 c6 85 fe 06 00 00 69 c6 85 ff 06 00 00 56}  //weight: 1, accuracy: High
        $x_1_2 = {c6 85 01 07 00 00 73 c6 85 02 07 00 00 73 c6 85 03 07 00 00 65 c6 85 04 07 00 00 72 c6 85 05 07 00 00 64 c6 85 06 07 00 00 64 c6 85 07 07 00 00 41 c6 85 08 07 00 00 63 c6 85 09 07 00 00 6f c6 85 0a 07 00 00 72 c6 85 0b 07 00 00 50 c6 85 0c 07 00 00 74 c6 85 0d 07 00 00 65 c6 85 0e 07 00 00 47}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_YBP_2147915757_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.YBP!MTB"
        threat_id = "2147915757"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {42 0f b7 34 27 42 88 34 3f 46 88 0c 27 41 01 f1 45 0f b6 c9 46 8a 0c 0f 45 30 08 49 ff c0 49 39 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CCJC_2147915867_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CCJC!MTB"
        threat_id = "2147915867"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 44 24 ?? 48 8b 0c 24 0f b6 04 08 0f b6 0d ?? ?? ?? ?? 31 c8 48 98 48 33 04 24 48 8b 4c 24 ?? 48 8b 14 24 88 04 11 48 8b 04 24 48 83 c0 01 48 89 04 24 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_AMAP_2147916100_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.AMAP!MTB"
        threat_id = "2147916100"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 c8 48 89 cf 49 f7 e0 48 89 d0 48 c1 e8 03 48 8d 14 40 48 8d 04 ?? 48 01 c0 48 29 c7 0f b6 44 3c 50 41 32 04 09 48 8b 54 24 ?? 88 04 0a 48 83 c1 01 48 39 4c 24 ?? 77}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_PR_2147916155_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.PR!MTB"
        threat_id = "2147916155"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 83 f8 60 4d 8d 40 01 48 0f 44 c3 41 ff c2 0f b6 4c 04 30 48 ff c0 41 30 48 ff 49 63 ca 48 81 f9 [0-4] 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CCJD_2147916405_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CCJD!MTB"
        threat_id = "2147916405"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 8b cc ba 10 dc 47 00 33 c9 41 b8 00 30 00 00 ff 15 ?? ?? ?? ?? 48 8b f8 b9 d0 07 00 00 ff 15 ?? ?? ?? ?? 41 b8 90 57 29 00 48 8d 15 ?? ?? ?? ?? 48 8b cf e8 ?? ?? ?? ?? 4c 8d 4c 24 20 ba 10 dc 47 00 41 b8 40 00 00 00 48 8b cf ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_GZM_2147916470_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.GZM!MTB"
        threat_id = "2147916470"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 8b d6 48 8b cb e8 ?? ?? ?? ?? b9 33 23 33 23 ff 15 ?? ?? ?? ?? ?? 48 8b 54 24 68 48 83 fa 0f}  //weight: 5, accuracy: Low
        $x_5_2 = {48 8b 04 25 60 00 00 00 45 33 c0 48 8b 50 18 4c 8b 52 10 49 8b 42 30 48 85 c0}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_AMAR_2147916557_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.AMAR!MTB"
        threat_id = "2147916557"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 c8 49 f7 e1 48 89 d0 48 c1 e8 ?? 48 8d 14 ?? 48 8d 04 ?? 48 01 c0 48 89 cb 48 29 c3 0f b6 84 1c ?? ?? ?? ?? 42 32 04 01 48 8b 94 24 ?? ?? ?? ?? 88 04 0a 48 83 c1 01 8b 84 24 ?? ?? ?? ?? 48 39 c8 77}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_GLX_2147916719_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.GLX!MTB"
        threat_id = "2147916719"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 14 08 44 31 c2 88 14 08 31 c0 48 b9 ?? ?? ?? ?? ?? ?? ?? ?? 48 29 c8 48 89 44 24 ?? e9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_GP_2147916806_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.GP!MTB"
        threat_id = "2147916806"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 ff c0 48 89 45 28 8b 85 48 01 00 00 48 39 45 28 73 32 48 8b 45 28 48 8b 8d 40 01 00 00 48 03 c8 48 8b c1 0f be 00 33 05 8d 15 01 00 33 05 8b 15 01 00 48 8b 4d 28 48 8b 55 08 48 03 d1 48 8b ca 88 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CCJF_2147916974_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CCJF!MTB"
        threat_id = "2147916974"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 04 41 59 31 c9 48 89 f2 41 b8 00 30 00 00 ff 15 ?? ?? ?? ?? 48 85 c0 0f 84 ?? ?? ?? ?? 49 89 c7 48 89 c1 48 89 da 49 89 f0 e8 ?? ?? ?? ?? 4c 8d 4d bc 41 c7 01 04 00 00 00 6a 10 41 58 4c 89 f9 48 89 f2 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_NPL_2147917103_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.NPL!MTB"
        threat_id = "2147917103"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff c8 83 c8 fc ff c0 48 98 ff c7 42 8a 0c 30 32 0c 16 41 32 0e 88 0a 48 ff c2 3b fd}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_OBS_2147917166_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.OBS!MTB"
        threat_id = "2147917166"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 89 db 29 fb d1 eb 01 fb c1 eb 04 8d 3c db 8d 3c 7f 44 89 db 29 fb 0f b6 1c 1a 42 32 1c 1e 42 88 1c 19 41 ff c3 41 83 fb 0a 48 89 c6 49 0f 44 f2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_KW_2147917208_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.KW!MTB"
        threat_id = "2147917208"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c2 25 03 ?? ?? ?? 7d ?? ff c8 83 c8 ?? ff c0 48 63 c8 ff c2 0f b6 44 0c ?? 32 03 41 88 84 18 ?? ?? ?? ?? 48 ff c3 41 3b d7 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_SZ_2147918385_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.SZ!MTB"
        threat_id = "2147918385"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 0a 83 f1 ?? 48 83 c2 01 88 4a ff 4c 39 c2 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CCJH_2147918444_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CCJH!MTB"
        threat_id = "2147918444"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {33 d2 41 83 f9 08 48 0f 45 d0 8a 04 0a 41 30 00 33 c0 41 83 f9 08 41 0f 45 c1 41 ff c2 49 ff c0 44 8d 48 01 48 8d 42 01 41 81 fa}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_W_2147918540_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.W!MTB"
        threat_id = "2147918540"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {41 53 80 f4 ?? 48 89 ca 89 c8 4c 8b 4d ?? 89 c0 4c 89 ca 89 d1 09 c0 48 8b 95}  //weight: 2, accuracy: Low
        $x_4_2 = {89 c6 4d 29 d0 48 33 45 ?? 88 cc 48 39 c9}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CBZ_2147918869_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CBZ!MTB"
        threat_id = "2147918869"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 c3 0f b6 c8 40 02 f1 40 02 f5 40 0f b6 ce 41 0f b6 44 8f 08 41 30 45 00 41 8b 44 8f 08 41 31 44 97 08 43 8b 44 a7 ?? 8d 0c 07 43 31 4c 87 08 48 83 7c 24 50 10 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_YI_2147919497_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.YI!MTB"
        threat_id = "2147919497"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {ff c0 89 44 24 ?? 48 63 44 24 ?? 8b 0d ?? ?? ?? ?? 83 c1 ?? 48 63 c9 48 8b 54 24 ?? 48 3b 04 ca 75}  //weight: 3, accuracy: Low
        $x_5_2 = {48 8b 4c 24 ?? 0f b7 04 41 8b 4c 24 ?? 33 c8 8b c1 48 98 48 33 05 ?? ?? ?? ?? 48 25 ?? ?? ?? ?? 48 63 4c 24 ?? 48 2b c1 89 44 24 ?? eb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_PT_2147919610_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.PT!MTB"
        threat_id = "2147919610"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {40 56 57 48 81 ec c8 03 00 00 48 8b 05 27 49 00 00 48 33 c4 48 89 84 24 b0 03 00 00 48 8d 05 75 2e 00 00 48 89 84 24 c8 00 00 00 48 8d 05 76 2e 00 00 48 89 84 24 c0 00 00 00 48 8d 84 24 b0 01 00 00 48 8d 0d 67 2e 00 00 48 8b f8 48 8b f1 b9 ?? 00 00 00 f3 a4 48 8d 84 24 ?? 01 00 00 48 8b f8 33 c0 b9 ?? 00 00 00 f3 aa 48 8d 84 24 b0 02 00 00 48 8d 0d 47 2e 00 00 48 8b f8 48 8b f1 b9 ?? 00 00 00 f3 a4 48 8d 84 24 ?? 02 00 00 48 8b f8 33 c0 b9 ?? 00 00 00 f3 aa 48 8d 0d 2f 2e 00 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_YBQ_2147919619_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.YBQ!MTB"
        threat_id = "2147919619"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 0f b6 44 31 08 0f b6 04 06 88 44 24 68 48 89 44 24 70 48 3d ff}  //weight: 1, accuracy: High
        $x_1_2 = {48 8b 54 24 70 0f b6 4c 24 60 48 8d 76 01 4c 8b 84 24 d8 00 00 00 48 c1 fa 04 c1 e1 02 09 ca 4d 85 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_UFO_2147919878_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.UFO!MTB"
        threat_id = "2147919878"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {ff c2 48 63 ca 8a 04 0c 42 88 04 1c 44 88 14 0c 42 0f b6 04 1c 49 03 c2 0f b6 c0 8a 0c 04 30 0b 48 ff c3 49 83 e8 01 75 a8}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_COS_2147919958_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.COS!MTB"
        threat_id = "2147919958"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {41 f7 e9 41 8b c9 41 ff c1 d1 fa 8b c2 c1 e8 1f 03 d0 6b c2 0b 2b c8 48 63 c1 48 03 c0 0f b6 84 c6 08 02 00 00 41 30 40 ff 49 83 ea 01 75 c8}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_KGD_2147920232_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.KGD!MTB"
        threat_id = "2147920232"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {49 8b c8 49 8b c1 49 f7 e0 48 c1 ea 04 48 6b c2 11 48 2b c8 8a 44 0c 40 42 30 44 05 80 49 ff c0 49 83 f8 0e 72 da}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_OKA_2147920385_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.OKA!MTB"
        threat_id = "2147920385"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 31 aa 48 ff c1 48 8b c1 48 2b c7 48 3b c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_YK_2147920483_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.YK!MTB"
        threat_id = "2147920483"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 f9 e8 ?? ?? ?? ?? 48 8b 8d ?? ?? ?? ?? 42 30 04 31 49 ff c6 4c 39 f3 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_PWH_2147920667_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.PWH!MTB"
        threat_id = "2147920667"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {48 63 ca 0f b6 c3 42 32 04 09 2a c2 ff c2 42 88 04 01 83 fa 20 72}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_YBR_2147920675_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.YBR!MTB"
        threat_id = "2147920675"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f b6 44 3c 50 43 32 04 02 48 8b 54 24 38 42 88 04 02 49 83 c0 01}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CCJI_2147920711_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CCJI!MTB"
        threat_id = "2147920711"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {45 31 c9 45 31 c0 31 d2 48 89 44 24 28 48 8b 4c 24 48 48 89 74 24 20 ff 15}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CCJJ_2147921105_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CCJJ!MTB"
        threat_id = "2147921105"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {33 d2 48 8d 45 d0 48 89 44 24 28 48 8d 05 a1 2c 00 00 48 89 44 24 20 ff 15}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_YTB_2147921723_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.YTB!MTB"
        threat_id = "2147921723"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 89 c2 25 ff ff ff 3f 48 d1 e2 48 c1 ea 1f 48 be 80 7f b1 d7 0d 00 00 00 48 01 f2 48 89 54 24 30 48 89 44 24 28}  //weight: 1, accuracy: High
        $x_1_2 = "9090909090909090904d5a4152554889e54881ec20000000488d1deaffffff488" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_BOW_2147921724_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.BOW!MTB"
        threat_id = "2147921724"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {42 8d 14 23 48 89 f9 30 54 18 08 e8 ?? ?? ?? ?? 48 8b 44 24 48 48 89 f2 48 89 f9 48 c1 fa 08 30 54 18 08 e8}  //weight: 5, accuracy: Low
        $x_4_2 = {48 89 f2 48 89 f9 48 c1 fa 10 48 c1 fe 18 30 54 18 08 e8 ?? ?? ?? ?? 48 8b 44 24 48 40 30 74 18 08 48 ff c3 eb}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CCJK_2147921775_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CCJK!MTB"
        threat_id = "2147921775"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {49 89 c6 89 d8 83 e0 ?? 41 01 de 44 32 74 05 ?? 46 32 34 3b 48 3b 5d ?? 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CCJL_2147921778_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CCJL!MTB"
        threat_id = "2147921778"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "OOpWE8DD" ascii //weight: 5
        $x_1_2 = "QtOf138M" ascii //weight: 1
        $x_1_3 = "UPhKga" ascii //weight: 1
        $x_1_4 = "WjYBl2410" ascii //weight: 1
        $x_1_5 = "ZWj90Ez" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_VV_2147921876_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.VV!MTB"
        threat_id = "2147921876"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b c3 48 ff c3 83 e0 03 42 8a 04 30 30 06 48 ff c6 48 ff c9 75 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_MBXY_2147922934_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MBXY!MTB"
        threat_id = "2147922934"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 ea 08 88 14 01 41 ff 81 ?? 00 00 00 49 63 89 ?? 00 00 00 49 8b 81 c8 00 00 00 44 88 04 01 41 ff 81 ?? 00 00 00 41 8b 41 40 41 8b 49 04 83 f1 01 0f af c1 41 89 41 40}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_AMJ_2147922946_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.AMJ!MTB"
        threat_id = "2147922946"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 2a c1 41 32 c0 88 44 15 ?? ff c2 44 8b 75 ?? 41 3b d6 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_YBN_2147922989_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.YBN!MTB"
        threat_id = "2147922989"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {42 30 8c 0d ?? ?? ?? ?? 41 f7 e8 c6 85 40 21 00 00 00 c1 fa 02 8b c2 c1 e8 ?? 03 d0 8d 04 d2 03 c0 44 2b c0 49 63 c0 0f b6 94 05 f8 00 00 00 42 30 94 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_AMM_2147923229_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.AMM!MTB"
        threat_id = "2147923229"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {45 0f b6 c0 46 0f b6 84 04 ?? ?? 00 00 44 30 04 ?? 48 ff c0 49 39 c4 75}  //weight: 4, accuracy: Low
        $x_1_2 = {89 c8 31 d2 f7 ?? 4c 8d 41 01 41 0f b6 04 17 88 84 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_KYI_2147923741_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.KYI!MTB"
        threat_id = "2147923741"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 63 c3 f0 42 80 34 30 79 ff c3 81 fb 3f b0 04 00}  //weight: 1, accuracy: High
        $x_2_2 = {33 d2 89 5c 24 28 48 8b c8 41 b9 00 10 00 00 c7 44 24 20 04 00 00 00 41 b8 00 00 c1 12 41 ff d5}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_KYI_2147923741_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.KYI!MTB"
        threat_id = "2147923741"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 45 07 28 00 2a 00 48 8d 05 c3 1b 00 00 c7 45 c7 30 00 00 00 48 89 45 0f 4c 8d 45 c7 48 8d 45 07 48 89 5d cf 0f 57 c0 48 89 45 d7 8d 53 0d c7 45 df 40 00 00 00 48 8d 4d bf f3 0f 7f 45 e7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_GV_2147923799_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.GV!MTB"
        threat_id = "2147923799"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b8 07 18 60 80 4d 8d 40 01 f7 e7 8b c7 8b cf 2b c2 ff c7 d1 e8 03 c2 c1 e8 0d 69 c0 a0 2a 00 00 2b c8 48 63 c1 0f b6 0c 18 41 30 48 ff 41 3b f9 7c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_ZGG_2147924315_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.ZGG!MTB"
        threat_id = "2147924315"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {49 ff c7 4c 89 f2 4d 89 f8 e8 ?? ?? ?? ?? 48 ba 00 00 00 00 ?? ?? ?? ?? 4d 89 e6 42 8d 04 2e 43 30 44 2e 08 4a 8d 2c 2e 4c 8b 77 08 49 85 16 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CCIP_2147924799_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CCIP!MTB"
        threat_id = "2147924799"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {88 18 48 8b 45 f0 48 89 c2 48 8b 4d 20 e8 ?? ?? ?? ?? 0f b6 10 8b 4d fc 31 ca 88 10 81 45 fc ?? ?? ?? ?? 48 83 45 f0 01 e9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_GM_2147924832_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.GM!MTB"
        threat_id = "2147924832"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "main.xorDecrypt" ascii //weight: 5
        $x_1_2 = "main.AesDecryptCFB" ascii //weight: 1
        $x_1_3 = "main.refun" ascii //weight: 1
        $x_1_4 = "main.run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_HZZ_2147925261_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.HZZ!MTB"
        threat_id = "2147925261"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 89 5c 24 08 48 89}  //weight: 1, accuracy: High
        $x_1_2 = {00 0a 73 25 09 64 32 30 25 3a 64 32 30 25 3a 64 32 30 25 20 64 32 30 25 2f 64 32 30 25 2f 64 32 30 25 09 30 09 44 00 00 00 0a 73 25 09 64 32 30 25 3a 64 32 30 25 3a 64 32 30 25 20 64 32 30 25 2f 64 32 30 25 2f 64 32 30 25 09 64 34 36 49 25 09 46}  //weight: 1, accuracy: High
        $x_1_3 = "0% d20%/d20%/d20" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_YMD_2147925551_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.YMD!MTB"
        threat_id = "2147925551"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {4d 63 db 44 89 df 48 69 ff ?? ?? ?? ?? 48 c1 ef 23 8d 1c bf 8d 1c 9b 01 fb 44 89 df 29 df 0f b6 1c 3a 42 32 1c 1e 42 88 1c 19 41 ff c3 41 83 fb 0b 4c 89 d6 49 0f 44 f1 eb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_MID_2147925552_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MID!MTB"
        threat_id = "2147925552"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {41 8b c2 4d 8d 5b 01 99 41 ff c2 41 f7 f8 48 63 c2 0f b6 4c 04 50 42 32 8c 1c ?? ?? 00 00 42 88 8c 1c ?? ?? 00 00 41 81 fa 7c 03 00 00 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_RZE_2147925553_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.RZE!MTB"
        threat_id = "2147925553"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {41 f7 e9 d1 fa 8b c2 c1 e8 1f 03 d0 41 8b c1 41 ff c1 8d 0c 52 c1 e1 ?? 2b c1 48 63 c8 42 0f b6 04 11 41 30 00 49 ff c0 49 8b c0 48 2b c6 48 3b c5 7c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_SIK_2147925735_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.SIK!MTB"
        threat_id = "2147925735"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 00 89 06 8b 44 24 50 48 8b bc 24 d0 00 00 00 48 8b b4 24 ?? ?? ?? ?? 83 e0 07 8a 04 07 42 30 04 0e 48 8b 05 ?? ?? ?? ?? 83 38 00 0f 84}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_YAE_2147925849_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.YAE!MTB"
        threat_id = "2147925849"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {49 8b c4 48 f7 e6 48 d1 ea 48 6b c2 0b 48 2b f0 32 5c 34 ?? 88 19 41 ff c6 49 63 f6}  //weight: 10, accuracy: Low
        $x_1_2 = {4b 7a 55 59 c7 ?? ?? ?? 56 55 35 44 66 ?? ?? ?? ?? 59 32 c6 44}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_RFAK_2147926030_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.RFAK!MTB"
        threat_id = "2147926030"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 63 c8 48 8d 54 24 70 48 03 d1 0f b6 0a 41 88 0a 44 88 1a 41 0f b6 12 49 03 d3 0f b6 ca 0f b6 54 0c 70 41 30 11 49 ff c1 48 83 eb 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_BCM_2147926296_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.BCM!MTB"
        threat_id = "2147926296"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {49 8b c0 48 f7 35 ?? ?? ?? ?? 0f b6 04 0a 43 30 04 01 49 ff c0 48 8b 8d ?? ?? ?? ?? 48 8b c1 4c 8b 8d ?? ?? ?? ?? 49 2b c1 4c 3b c0 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_HZP_2147927267_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.HZP!MTB"
        threat_id = "2147927267"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {41 fe c1 45 0f b6 c9 4b 8d 14 8e 44 8b 42 08 43 8d 04 03 44 0f b6 d8 43 8b 4c 9e ?? 89 4a 08 47 89 44 9e ?? 44 02 c1 41 0f b6 c0 41 0f b6 4c 86 ?? 41 30 0a 4d 8d 52 01 48 83 eb 01 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_KEP_2147928000_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.KEP!MTB"
        threat_id = "2147928000"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b cb 41 8b d8 0f b6 14 01 41 8b c1 02 14 39 c1 e0 04 41 33 c1 41 88 14 38 44 3b 05 ?? ?? ?? ?? 89 05 ?? 2e 00 00 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_NC_2147928169_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.NC!MTB"
        threat_id = "2147928169"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {40 53 56 48 83 ec 48 45 8b d0 8d 99 ac fd ff ff 41 81 f2 d9 03 00 00 8d 83 1f 03 00 00 44 8d 9a b5 fa ff ff 8b f1 44 3b d0}  //weight: 2, accuracy: High
        $x_1_2 = {eb 4c 8b c5 25 c1 13 00 00 41 03 c0 3b f0 74 3e}  //weight: 1, accuracy: High
        $x_1_3 = "MtdkvsQGzCvJ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_GB_2147928172_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.GB!MTB"
        threat_id = "2147928172"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 8a 14 10}  //weight: 1, accuracy: High
        $x_1_2 = {44 30 14 0f 48 ff c1 48 89 c8 48 81 f9 [0-4] 0f 86}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_GD_2147928271_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.GD!MTB"
        threat_id = "2147928271"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {41 8b c8 83 e1 3f 2b d1 8a ca 48 8b d0 48 d3 ca 49 33 d0 4b 87 94 fe e8 15 04 00 eb 2d}  //weight: 5, accuracy: High
        $x_4_2 = "setup" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_GD_2147928271_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.GD!MTB"
        threat_id = "2147928271"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 31 d2 49 f7 f0}  //weight: 1, accuracy: High
        $x_1_2 = {45 8a 14 11}  //weight: 1, accuracy: High
        $x_1_3 = {44 30 14 0f}  //weight: 1, accuracy: High
        $x_1_4 = {48 89 c8 48 81 f9 [0-4] 76}  //weight: 1, accuracy: Low
        $x_1_5 = "on_avast_dll_unload" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_LUC_2147928289_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.LUC!MTB"
        threat_id = "2147928289"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 c1 48 8b 8c 24 ?? ?? ?? ?? 88 01 0f be 44 24 51 83 e8 33 88 44 24 51 c7 84 24 ?? ?? ?? ?? 2a 7e 00 00 0f b6 44 24 50 05 a0 00 00 00 48 8b 8c 24 80 4f 00 00 88 01 0f b6 44 24 50 35 ef 00 00 00 48 8b 8c 24 ?? ?? ?? ?? 88 01 e9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_GA_2147928374_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.GA!MTB"
        threat_id = "2147928374"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "OFtP7URkZYOH*+%3&UIHd" ascii //weight: 1
        $x_1_2 = "lease\\x64\\overseer.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_AMCS_2147928390_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.AMCS!MTB"
        threat_id = "2147928390"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 89 c1 41 83 e1 ?? 47 8a 0c 08 44 30 0c 01 48 ff c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_LM_2147928930_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.LM!MTB"
        threat_id = "2147928930"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 c2 99 41 23 d7 03 c2 41 23 c7 2b c2 8a 54 04 30 41 30 10 49 ff c0 49 83 e9 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_SHC_2147929158_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.SHC!MTB"
        threat_id = "2147929158"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 89 44 24 48 48 8b 7c 24 48 48 8b 74 24 40 48 8b 4c 24 30 f3 a4 ff 54 24 48}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_MBWJ_2147929268_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MBWJ!MTB"
        threat_id = "2147929268"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Go build ID: \"_zYEPStlItXQSIZx" ascii //weight: 2
        $x_1_2 = "axy1/TpcPcZwBtQYcCL6rREEc/8XLJ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_RKB_2147929389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.RKB!MTB"
        threat_id = "2147929389"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f be 44 24 07 48 8b 4c 24 10 48 8b 54 24 08 44 0f be 04 11 41 31 c0 44 88 04 11 48 8b 44 24 08 48 83 c0 01 48 89 44 24 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_MBV_2147929426_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MBV!MTB"
        threat_id = "2147929426"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {ff c0 89 44 24 54 8b 44 24 50 39 44 24 ?? 73 20 48 63 44 24 ?? 48 8b 4c 24 58 0f be 04 01 83 f0 45 48 63 4c 24 54 48 8b ?? 24 58 88 04 0a eb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_TC_2147929514_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.TC!MTB"
        threat_id = "2147929514"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4c 8b 74 24 68 4c 8b 6c 24 60 48 8b 5c 24 58 41 ff d4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_OMK_2147929736_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.OMK!MTB"
        threat_id = "2147929736"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 c9 2b c1 48 8d 0d 5e 21 00 00 42 0f b6 04 20 32 04 3e 0f b6 d0 88 17 e8 d4 fd ff ff ff c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_ASD_2147929793_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.ASD!MTB"
        threat_id = "2147929793"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Access violation caught, decrypting memory" ascii //weight: 1
        $x_1_2 = "drop of the panic payload panicked" ascii //weight: 1
        $x_2_3 = {31 c0 48 39 c2 74 08 f6 14 01 48 ff c0 eb f3}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_DAKU_2147930036_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.DAKU!MTB"
        threat_id = "2147930036"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {99 81 e2 ff 00 00 00 03 c2 25 ff 00 00 00 2b c2 89 85 a4 02 00 00 48 63 85 c4 02 00 00 48 63 8d a4 02 00 00 0f b6 4c 0d 10 48 8b 95 80 04 00 00 0f b6 04 02 33 c1 48 63 8d c4 02 00 00 48 8b 95 80 04 00 00 88 04 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_GKN_2147931007_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.GKN!MTB"
        threat_id = "2147931007"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {65 48 8b 04 25 60 00 00 00 48 89 44 24 38 48 8b 44 24 38 48 8b 40 18 48 89 44 24 40 48 8b 44 24 40 48 83 c0 20 48 89 44 24 30 48 8b 44 24 30 48 8b 00 48 89 44 24 20 48 8b 44 24 30 48 39 44 24 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_ZZV_2147931292_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.ZZV!MTB"
        threat_id = "2147931292"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {41 ff c0 49 63 c8 48 8d 14 24 48 03 d1 0f b6 0a 41 88 0a 44 88 0a 45 02 0a 41 0f b6 c9 0f b6 14 0c 41 30 13 49 ff c3 48 83 eb 01 75 9d}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_ASK_2147931328_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.ASK!MTB"
        threat_id = "2147931328"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {45 8a 34 11 44 30 34 0f 48 ff c1 48 89 c8 48 81 f9 ff c5 06 00 0f}  //weight: 4, accuracy: High
        $x_1_2 = "H1D^3h@vEY^bp)LUgl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_GE_2147931392_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.GE!MTB"
        threat_id = "2147931392"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 44 01 da d8 62 26 a0 c2 85 80 ae e6 a6 bf 47 f5 30 93 f5 1b ee e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_COP_2147931403_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.COP!MTB"
        threat_id = "2147931403"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 89 c1 48 c1 e1 06 48 8d 15 b6 e9 2d 00 48 8d 0c 0a 48 8d 49 08 48 ff c0 44 0f 11 39 48 83 f8 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_2147931960_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MTV!MTB"
        threat_id = "2147931960"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTV: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 0f af c1 66 89 05 59 c1 19 00 8b 44 24 60 35 a5 00 00 00 48 98 48 89 84 24 ?? ?? ?? ?? 8b 05 ac e4 bf 00 48 89 05 c5 c1 19 00 0f b6 05 ?? ?? ?? ?? 0f be c0 2d 3d 9b ad 9d 89 44 24 70 0f be 44 24 43 0f b6 4c 24 40 0f b6 c9 2b c1 0f be 4c 24 43 2b c8 8b c1 88 44 24 43 e9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_OTV_2147931961_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.OTV!MTB"
        threat_id = "2147931961"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2d cb 3d 00 00 88 44 24 31 48 8b 05 16 2c 18 00 48 69 c0 63 4f 00 00 0f b7 0d ?? ?? ?? ?? 48 03 c8 48 8b c1 66 89 05 ?? ?? ?? ?? 48 63 44 24 54 48 b9 07 61 c5 2f d5 28 03 00 48 2b c1 89 05 eb 2b 18 00 48 8b 44 24 78 48 8b 0d e7 2b 18 00 48 2b c8 48 8b c1 48 8b 0d ?? ?? ?? ?? 48 33 c8 48 8b c1 48 89 05 cd 2b 18 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_DLR_2147932174_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.DLR!MTB"
        threat_id = "2147932174"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {c7 44 24 20 40 00 00 00 41 b9 00 30 00 00 49 89 d0 ba 00 00 00 00 48 89 c1 48 8b 05 66 6a 00 00 ff d0}  //weight: 2, accuracy: High
        $x_1_2 = "maskdesk.info" ascii //weight: 1
        $x_1_3 = "/file" ascii //weight: 1
        $x_1_4 = "ResumeThread" ascii //weight: 1
        $x_1_5 = "System32\\notepad.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_NQP_2147932536_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.NQP!MTB"
        threat_id = "2147932536"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {ff c1 4c 63 f1 41 8d 53 ?? 41 0f b6 c8 4d 03 f2 80 e1 f7 83 e2 07 41 32 c8 41 30 0e 41 0f b6 c8 80 e1 fb 41 32 c8 42 30 0c 12 41 8d 4b fd 81 e1 07 00 00 80 7d}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_AZP_2147932865_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.AZP!MTB"
        threat_id = "2147932865"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {31 fd 66 0f 6e e5 66 0f 70 e4 ?? 66 0f 6f ec 66 0f db e8 66 0f db e1 66 0f 76 e1 66 0f db e2 66 0f 76 e8 66 0f db eb 66 0f ef ec c1 ed 08 66 0f 70 e5 ?? 66 0f ef e5 66 0f 70 ec 55 66 0f ef ec 66 0f 7e ef 31 ef 0f b6 2e 48 ff c6 40 84 ed 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_ASL_2147932883_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.ASL!MTB"
        threat_id = "2147932883"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0f b6 54 24 ?? 03 ca 03 c1 83 f0 08 88 44 24 ?? 48 8b 44 24 ?? 48 ff c0 48 89 44 24 ?? eb}  //weight: 3, accuracy: Low
        $x_1_2 = {99 83 e0 01 33 c2 2b c2 48 63 4c 24}  //weight: 1, accuracy: High
        $x_1_3 = {33 ca 03 c1 25 ff 00 00 00 88 04 24 0f b6 04 24 48 83 c4 18}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_GNE_2147932887_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.GNE!MTB"
        threat_id = "2147932887"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {99 83 e0 01 33 c2 2b c2 48 63 4c 24 48 48 8b 94 24 b8 00 00 00 88 04 0a eb ?? 41 b9 40 00 00 00 41 b8 00 30 00 00 ba a8 c0 5f 00 33 c9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_WVY_2147933265_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.WVY!MTB"
        threat_id = "2147933265"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 c2 88 55 77 30 c1 88 4d 76 31 c0 48 8d 0d a5 eb 01 00 48 63 14 08 81 74 95 e0 27 1e 00 00 48 83 c0 04 48 83 f8 68}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_SMN_2147933704_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.SMN!MTB"
        threat_id = "2147933704"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 b8 76 4e af cc fb a9 1d 4e 8b 14 01 48 8b 0d a0 3b 0f 00 8b 0c 01 41 89 d0 41 ff c8 41 0f af d0 41 88 d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_MLZ_2147933859_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MLZ!MTB"
        threat_id = "2147933859"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 8b c5 4c 33 c1 49 63 ca 49 f7 e0 41 ff c2 48 c1 ea 0a 48 69 c2 ?? ?? ?? ?? 33 d2 4c 2b c0 48 8b c1 4d 31 04 39 48 33 05 2e 59 0b 00 48 03 c1 48 f7 35 e4 58 0b 00 48 89 15 dd 58 0b 00 41 81 fa 04 19 00 00 7e}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_PLZ_2147933922_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.PLZ!MTB"
        threat_id = "2147933922"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {44 01 c8 99 41 f7 fb 48 63 c2 8a 14 01 49 89 c1 42 88 14 29 40 88 3c 01 42 02 3c 29 40 0f b6 ff 8a 04 39 43 30 04 20 49 ff c4 eb ba}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_BCP_2147934074_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.BCP!MTB"
        threat_id = "2147934074"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {32 44 35 00 89 54 24 38 8b 54 24 38 83 e2 01 01 d0 88 04 33 48 ff c6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_GF_2147934168_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.GF!MTB"
        threat_id = "2147934168"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 81 b0 00 00 00 8b 05 ?? ?? ?? ?? 01 43 30 48 8b 05 ?? ?? ?? ?? 8b 88 88 00 00 00 2b 48 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_BJK_2147934173_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.BJK!MTB"
        threat_id = "2147934173"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 8b ac 00 00 00 2b c1 48 63 4b 54 01 83 b0 00 00 00 0f b6 c2 0f b6 53 50 0f af d0 48 8b 83 c8 00 00 00 88 14 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CHL_2147935416_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CHL!MTB"
        threat_id = "2147935416"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4d 63 ce 4c 3b 0b 73 0b 0f b6 d4 41 ff c6 42 88 54 0d 00 4d 63 ce 4c 3b 0b 73 08 42 88 44 0d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_DCP_2147935432_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.DCP!MTB"
        threat_id = "2147935432"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 f7 f1 48 8b c2 48 8b d0 48 8b 4c 24 50 e8 ?? ?? ?? ?? 0f be 00 48 8b 4c 24 20 48 8b 54 24 40 48 03 d1 48 8b ca 0f be 09 33 c8 8b c1 48 8b 4c 24 20 48 8b 54 24 40 48 03 d1 48 8b ca 88 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_NIT_2147935435_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.NIT!MTB"
        threat_id = "2147935435"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {4d 8d 48 1f 49 83 e1 e0 4d 8b d9 49 c1 eb 05 47 8b 9c 9a e0 c4 55 00 4d 03 da 41 ff e3 c4 a1 7e 6f 8c 0a 00 ff ff ff c4 a1 7e 7f 8c 09 00 ff ff ff c4 a1 7e 6f 8c 0a 20 ff ff ff c4 a1 7e 7f 8c 09 20 ff ff ff c4 a1 7e 6f 8c 0a 40 ff ff ff c4 a1 7e 7f 8c 09 40 ff ff ff c4 a1 7e 6f 8c 0a 60 ff ff ff c4 a1 7e 7f 8c 09 60 ff ff ff c4 a1 7e 6f 4c 0a 80 c4 a1 7e 7f 4c 09 80 c4 a1 7e 6f 4c 0a a0 c4 a1 7e 7f 4c 09 a0 c4 a1 7e 6f 4c 0a c0 c4 a1 7e 7f 4c 09 c0 c4 a1 7e 7f 6c 01 e0 c5 fe 7f 00 c5 f8 77}  //weight: 2, accuracy: High
        $x_1_2 = "checking sandbox via sleep time" ascii //weight: 1
        $x_1_3 = "previously been poisoned" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_GG_2147935910_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.GG!MTB"
        threat_id = "2147935910"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 0f b6 ca 46 0f b6 8c 0c ?? ?? ?? ?? 44 32 0c 0a 44 88 0c 17 4c 89 c2 49 81 f8 09 0e 04 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CCJV_2147935992_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CCJV!MTB"
        threat_id = "2147935992"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 63 04 24 48 8b 4c 24 ?? 0f b6 04 01 33 44 24 30 48 63 0c 24 48 8b 54 24 ?? 88 04 0a eb}  //weight: 2, accuracy: Low
        $x_1_2 = {8b 44 24 4c 83 f0 ?? 8b 4c 24 20 03 c8 8b c1 89 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CS_2147936705_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CS!MTB"
        threat_id = "2147936705"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 63 c2 48 8d 8d ?? ?? ?? ?? 48 03 c8 0f b6 01 41 88 04 30 44 88 09 41 0f b6 04 30 41 03 c1 0f b6 c0 0f b6 8c 05 ?? ?? ?? ?? 41 30 0a 49 ff c2 49 83 eb ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_OPZ_2147936827_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.OPZ!MTB"
        threat_id = "2147936827"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {89 f1 c1 e9 02 f3 0f 10 44 24 ?? 49 89 d8 49 8d 40 04 f3 41 0f 10 08 0f 57 c8 f3 41 0f 11 08 49 89 c0 ff c9 75}  //weight: 4, accuracy: Low
        $x_5_2 = {89 c9 45 31 c0 46 8a 4c 04 ?? 46 30 0c 00 49 ff c0 4c 39 c1 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_AML_2147936983_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.AML!MTB"
        threat_id = "2147936983"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {47 88 54 01 ff 48 ff c6 4c 89 d8 4c 89 e2 48 39 f3 0f 8e ?? 00 00 00 44 0f b6 14 06 48 85 c9 0f 84 ?? 00 00 00 49 89 c3 48 89 f0 49 89 d4 48 99 48 f7 f9 0f 1f 44 00 00 48 39 ca 0f 83 ?? 00 00 00 49 ff c1 42 0f b6 14 22 41 31 d2 4c 39 cf 73}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_BNZ_2147937040_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.BNZ!MTB"
        threat_id = "2147937040"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {ff c0 89 44 24 20 8b 44 24 58 39 44 24 20 7d 5d 48 63 44 24 ?? 48 8b 4c 24 50 0f b6 04 01 33 44 24 60 48 63 4c 24 ?? 48 8b 54 24 28 88 04 0a 48 63 44 24 20 48 8b 4c 24 28}  //weight: 5, accuracy: Low
        $x_4_2 = {99 81 e2 ff 00 00 00 03 c2 25 ff 00 00 00 2b c2 8b 4c 24 ?? 33 c8 8b c1 48 63 4c 24 20 48 8b 54 24 28 88 04 0a eb}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_BSM_2147937167_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.BSM!MTB"
        threat_id = "2147937167"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 98 48 8d 15 40 1a 00 00 0f b6 14 10 8b 85 fc 39 04 00 48 98 0f b6 44 05 c0 31 d0 8b 95 f8 39 04 00 48 63 d2 88 44 15 e0 83 85 fc 39 04 00 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_JIP_2147937257_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.JIP!MTB"
        threat_id = "2147937257"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 c3 39 f7 7e ?? 41 ff d7 48 89 f0 83 e0 ?? 45 8a 2c 04 41 ff d7 44 32 6c 35 ?? 44 88 2c 33 48 ff c6 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_JOP_2147937258_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.JOP!MTB"
        threat_id = "2147937258"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 89 c0 49 83 e0 ?? 75 ?? 88 d3 eb ?? 88 cb 30 1c 07 48 ff c0 48 39 f0 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_JKT_2147937259_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.JKT!MTB"
        threat_id = "2147937259"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 d2 48 8d 0c 2f 48 8b c7 48 ff c7 49 f7 f1 0f b6 44 14 20 32 04 0b 88 01 48 3b fe 72 e2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_VZZ_2147937281_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.VZZ!MTB"
        threat_id = "2147937281"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {ff c1 0f b6 c9 44 0f b6 4c 0d ?? 44 00 ca 44 0f b6 c2 46 0f b6 54 05 d0 44 88 54 0d d0 46 88 4c 05 d0 44 02 4c 0d d0 45 0f b6 c9 46 0f b6 4c 0d d0 45 30 0c 07 48 ff c0 49 39 c6 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_DDZ_2147937575_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.DDZ!MTB"
        threat_id = "2147937575"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b6 d1 43 0f b6 0c 0b 42 0f b6 04 0a 43 88 04 0b 42 88 0c 0a 41 0f b6 81 00 01 00 00 42 0f b6 14 08 41 0f b6 81 ?? ?? ?? ?? 42 0f b6 0c 08 03 d1 81 e2 ff 00 00 80 7d ?? ff ca 81 ca 00 ff ff ff ff c2 48 63 c2 49 ff c2 42 0f b6 0c 08 41 30 4a ff 49 ff c8 0f 85}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_FIZ_2147937649_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.FIZ!MTB"
        threat_id = "2147937649"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b c3 ff c3 83 e0 07 42 8a 04 20 30 07 48 ff c7 3b de 7c e6}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_QQK_2147937869_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.QQK!MTB"
        threat_id = "2147937869"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {4d 01 ef 89 bd e2 fe ff ff 4c 31 8d c7 fe ff ff 4c 8b 9d 4b ff ff ff 66 89 c2 8b 95 31 ff ff ff 21 c1 89 8d 0f ff ff ff 4c 2b bd 25 ff ff ff 0f b6 c8 89 c0 4c 31 bd ?? ?? ?? ?? 49 c7 c2 12 d2 00 00 4c 89 3d 9e e6 02 00 4c 8b 85 ?? ?? ?? ?? 4c 01 c1 49 c7 c0 21 e0 00 00 89 85 10 ff ff ff 48 ff 04 24 48 83 3c 24 03 0f 8e}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_MBX_2147938579_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MBX!MTB"
        threat_id = "2147938579"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 0e 48 01 d9 48 8d 54 24 2c 49 89 f8 e8 d9 6b 00 00 48 01 fb 48 89 5e 10 48 83 c4 30}  //weight: 1, accuracy: High
        $x_2_2 = {4c bc 00 00 00 30 02 00 00 be 00 00 00 18 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 40 2e 64 61 74 61 00 00 00 f8 02 00 00 00 f0 02}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_MBY_2147938580_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.MBY!MTB"
        threat_id = "2147938580"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 89 5c 24 08 48 89 6c 24 10 48 89 74 24 18 48 89 7c 24 20 33 ff 4d 8d 59 ff 49 8b e8 48 8b da 48 8b f1 4c 3b}  //weight: 2, accuracy: High
        $x_1_2 = {dc 97 00 00 00 f0 00 00 00 98 00 00 00 e2 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 40 2e 64 61 74 61}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_GTB_2147939116_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.GTB!MTB"
        threat_id = "2147939116"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 89 da 48 89 44 24 ?? 4d 63 c8 41 83 c0 ?? 47 0f b6 0c 0a 44 30 0a 4c 8d 4a ?? 4d 39 cb ?? ?? 41 83 f8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_GVA_2147939450_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.GVA!MTB"
        threat_id = "2147939450"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 2b c1 48 89 44 24 78 48 8b 44 24 20 48 ff c0 48 89 44 24 20 8b 44 24 78 89 44 24 5c 8b 44 24 50 c1 e0 12 8b 4c 24 54 c1 e1 0c 0b c1 8b 4c 24 58 c1 e1 06 0b c1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_WQ_2147939948_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.WQ!MTB"
        threat_id = "2147939948"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b7 47 14 48 8d 14 9b 4c 01 e8 48 8d 34 d0 4c 89 f2 48 89 f1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_IV_2147940480_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.IV!MTB"
        threat_id = "2147940480"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 63 c2 48 8d 8c 24 ?? ?? ?? ?? 48 03 c8 0f b6 01 41 88 04 30 44 88 09 41 0f b6 0c 30 49 03 c9 0f b6 c1 0f b6 8c 04 ?? ?? ?? ?? 41 30 0a 49 ff c2 49 83 eb ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CCJX_2147941334_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CCJX!MTB"
        threat_id = "2147941334"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 f7 f1 48 8b c2 0f b6 c8 8b 44 24 ?? d3 e8 8b 4c 24 ?? 33 c8 8b c1 8b 4c 24 ?? 81 e1 ?? ?? ?? ?? 33 c1 25}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_AQD_2147941407_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.AQD!MTB"
        threat_id = "2147941407"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 c1 99 81 e2 ff 00 00 00 03 c2 25 ff 00 00 00 2b c2 89 44 24 10 8b 44 24 0c 48 63 4c 24 10 0f b6 4c 0c 20 48 8b 94 24 30 02 00 00 0f b6 04 02 33 c1 8b 4c 24 0c 48 8b 94 24 30 02 00 00 88 04 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_GLA_2147941525_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.GLA!MTB"
        threat_id = "2147941525"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {45 0f b6 7c 01 02 48 ff c6 45 31 e7 45 31 ef}  //weight: 4, accuracy: High
        $x_4_2 = {44 88 7c 1e ff 48 ff c0 4c 39 d8}  //weight: 4, accuracy: High
        $x_1_3 = "almounah/go-buena-clr" ascii //weight: 1
        $x_1_4 = "buenavillage" ascii //weight: 1
        $x_1_5 = "Go build ID:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_RY_2147941904_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.RY!MTB"
        threat_id = "2147941904"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 14 08 41 30 14 08 48 8d 51 01 48 89 d1 49 39 d1 75 ed}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_RY_2147941904_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.RY!MTB"
        threat_id = "2147941904"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 04 24 0f b6 4c 24 30 48 8b 54 24 20 0f be 04 02 33 c1 8b 0c 24 48 8b 54 24 20 88 04 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_ELM_2147943915_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.ELM!MTB"
        threat_id = "2147943915"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 44 24 08 44 8a 0c 01 48 8b 44 24 08 44 32 0c 02 45 0f b6 c9 44 0b 4c 24 04 4c 8b 54 24 08 49 83 c2 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_GZZ_2147944853_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.GZZ!MTB"
        threat_id = "2147944853"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 c9 c7 44 24 ?? 00 00 00 00 ba ?? ?? ?? ?? 41 b8 00 30 00 00 44 8d 49 ?? ff 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_GZZ_2147944853_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.GZZ!MTB"
        threat_id = "2147944853"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {46 88 24 30 49 ff c6 4c 89 b5 ?? ?? ?? ?? 49 81 fe ?? ?? ?? ?? ?? ?? 44 89 f0 83 e0 0f 47 0f b6 24 3e 44 32 64 05 b0 4c 3b b5}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_IS_2147945069_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.IS!MTB"
        threat_id = "2147945069"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 98 48 8b 95 ?? ?? ?? ?? 48 01 d0 0f b6 00 32 85 ?? ?? ?? ?? 48 8b 8d ?? ?? ?? ?? 8b 95 ?? ?? ?? ?? 48 63 d2 88 04 11 83 85 ?? ?? ?? ?? ?? 8b 95 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 39 c2 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_JHG_2147945074_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.JHG!MTB"
        threat_id = "2147945074"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 c8 49 f7 e0 48 c1 ea ?? 48 8d 04 52 48 89 ca 48 01 c0 48 29 c2 0f b6 44 14 ?? 32 04 0e 88 04 0b 48 83 c1 ?? 48 81 f9 ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_HAZ_2147945516_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.HAZ!MTB"
        threat_id = "2147945516"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 c9 41 b9 40 00 00 00 41 b8 00 30 00 00 41 ff d6 48 8b f0}  //weight: 5, accuracy: High
        $x_4_2 = {8b d0 ff c0 0f b6 0c 17 88 0c 16 41 3b 44 24 ?? 72}  //weight: 4, accuracy: Low
        $x_1_3 = "ReflectiveLoader" ascii //weight: 1
        $x_1_4 = "SELECT host_key, name, encrypted_value FROM cookies;" ascii //weight: 1
        $x_1_5 = "chrome_decrypt.log" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_HMZ_2147945517_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.HMZ!MTB"
        threat_id = "2147945517"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 98 0f b6 44 05 b0 83 f0 0a 8b 95 4c 03 00 00 48 63 d2 88 44 15 b0 83 85 4c 03 00 00 01 8b 85 4c 03 00 00 3b 85 ?? 03 00 00 7c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_GZK_2147946169_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.GZK!MTB"
        threat_id = "2147946169"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {4c 03 d2 48 03 fa 45 33 c9 45 8b 02 41 8b c9 4c 03 c2 41 8a 00 49 ff c0 c1 c9 0d 0f be c0 03 c8 41 8a 00 84 c0}  //weight: 5, accuracy: High
        $x_5_2 = {50 33 c9 41 b8 00 30 00 00 44 8d 49 40 41 ff}  //weight: 5, accuracy: High
        $x_1_3 = "?ReflectiveLoader@@YA_KPEAX@Z" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_GZQ_2147946290_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.GZQ!MTB"
        threat_id = "2147946290"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {44 88 3c 30 48 ff c6 48 89 b5 ?? ?? ?? ?? 48 81 fe ?? ?? ?? ?? ?? ?? 89 f0 83 e0 0f 46 0f b6 3c 36 44 32 bc 05 ?? ?? ?? ?? 48 3b b5}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_GVD_2147946352_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.GVD!MTB"
        threat_id = "2147946352"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 03 c8 0f b6 01 41 88 04 38 44 88 09 41 0f b6 0c 38 49 03 c9 0f b6 c1 0f b6 4c 04 20 30 4d 00 48 ff c5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_PGCS_2147947094_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.PGCS!MTB"
        threat_id = "2147947094"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {31 d2 f7 f1 8b 44 24 ?? 89 d1 0f b6 4c 0c ?? 31 c8 88 c2 48 8b 44 24 ?? 8b 4c 24 ?? 88 14 08 8b 44 24 ?? 83 c0 01 89 44 24 ?? eb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_IT_2147947411_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.IT!MTB"
        threat_id = "2147947411"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 45 f8 48 8b 55 10 48 8b 45 f8 41 b8 0a 00 00 00 48 89 c1 48 8b 05 ?? ?? ?? ?? ff d0 48 89 45 f0 48 8b 55 f0 48 8b 45 f8 48 89 c1 48 8b 05 ?? ?? ?? ?? ff d0 48 89 45 e8 48 8b 55 f0 48 8b 45 f8 48 89 c1 48 8b 05 ?? ?? ?? ?? ff d0 48 8b 55 20 89 02 48 8b 45 e8 48 89 c1 48 8b 05 ?? ?? ?? ?? ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_FONE_2147948047_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.FONE!MTB"
        threat_id = "2147948047"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 98 0f b6 44 05 90 88 85 96 00 00 00 48 8b 95 c0 00 00 00 48 8b 85 98 00 00 00 48 01 d0 0f b6 00 48 8b 8d c8 00 00 00 48 8b 95 98 00 00 00 48 01 ca 32 85 96 00 00 00 88 02 48 83 85 98 00 00 00 01 48 8b 85 98 00 00 00 48 3b 85 d0 00 00 00 0f 82 01 ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_FTW_2147948050_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.FTW!MTB"
        threat_id = "2147948050"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 98 0f b6 44 05 c0 88 85 fe 08 00 00 48 8d 95 d0 00 00 00 48 8b 85 28 09 00 00 48 01 d0 0f b6 00 48 8b 8d 08 09 00 00 48 8b 95 28 09 00 00 48 01 ca 32 85 fe 08 00 00 88 02 48 83 85 28 09 00 00 01 48 8b 85 28 09 00 00 48 3b 85 18 09 00 00 0f 82 01 ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_FTA_2147948170_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.FTA!MTB"
        threat_id = "2147948170"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 63 f6 89 f3 49 0f af db 48 c1 eb 24 8d 2c 5b c1 e5 03 29 eb 01 f3 0f b6 1c 1a 32 1c 37 88 1c 31 ff c6 83 fe 0d 4c 89 d7 49 0f 44 f9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_VST_2147948232_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.VST!MTB"
        threat_id = "2147948232"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 98 0f b6 84 05 90 00 00 00 88 85 96 01 00 00 48 8b 95 c0 01 00 00 48 8b 85 98 01 00 00 48 01 d0 0f b6 00 48 8b 8d c8 01 00 00 48 8b 95 98 01 00 00 48 01 ca 32 85 96 01 00 00 88 02 48 83 85 98 01 00 00 01 48 8b 85 98 01 00 00 48 3b 85 d0 01 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_INC_2147948325_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.INC!MTB"
        threat_id = "2147948325"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {32 85 fe 17 00 00 89 c2 8b 85 e8 18 00 00 48 98 88 94 05 b0 07 00 00 8b 85 e8 18 00 00 48 98 0f b6 84 05 b0 07 00 00 32 85 ff 18 00 00 89 c2 8b 85 e8 18 00 00 48 98 88 94 05 b0 07 00 00 80 85 ff 18 00 00 01 83 85 e8 18 00 00 01 8b 85 e8 18 00 00 3d 1f 08 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_TNN_2147948668_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.TNN!MTB"
        threat_id = "2147948668"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 1c 06 32 1f 88 1c 06 40 47 29 d7 81 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_GCMD_2147948766_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.GCMD!MTB"
        threat_id = "2147948766"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 63 c1 0f b6 4c 84 ?? 41 30 08 49 ff c0 49 83 eb 01 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_PLM_2147948767_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.PLM!MTB"
        threat_id = "2147948767"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 08 48 8b 55 ?? 8b 45 ?? 48 01 d0 44 89 ca 31 ca 88 10 83 45 fc 01 8b 45 ?? 39 45 ?? 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_CLM_2147948768_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.CLM!MTB"
        threat_id = "2147948768"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {45 0f b6 04 10 45 31 c1 44 88 0c 3e 48 8d 57 ?? 48 89 f0 48 39 d3 7e ?? 4c 8b 05 ?? ?? ?? ?? 44 0f b6 0c 10}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_GVC_2147948842_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.GVC!MTB"
        threat_id = "2147948842"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b f8 8d 4a 04 ff 15 ?? ?? ?? ?? 48 8b c8 48 8d 54 24 68 48 8b d8 ff 15 ?? ?? ?? ?? 85 c0 [0-10] 48 8b cb 39 7c 24 74 ?? ?? 48 8d 54 24 68 ff 15 ?? ?? ?? ?? 85 c0 75 e8}  //weight: 2, accuracy: Low
        $x_1_2 = "Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_GVF_2147948846_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.GVF!MTB"
        threat_id = "2147948846"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 03 c8 0f b6 01 41 88 04 32 44 88 01 41 0f b6 04 32 4c 03 c0 41 0f b6 c0 0f b6 8c 04 10 03 00 00 41 30 09 49 ff c1 49 83 ee 01 75 90}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_GVH_2147949035_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.GVH!MTB"
        threat_id = "2147949035"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 8b 04 24 48 ff c0 48 89 04 24 48 8b 44 24 38 48 39 04 24 73 40}  //weight: 2, accuracy: High
        $x_1_2 = {33 d2 48 8b 04 24 48 f7 74 24 28 48 8b c2 48 8b 4c 24 20 0f be 04 01 48 8b 0c 24 48 8b 54 24 30 48 03 d1 48 8b ca 0f be 09 33 c8 8b c1 48 8b 0c 24 48 8b 54 24 30 48 03 d1 48 8b ca 88 01 eb aa}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_GVJ_2147949373_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.GVJ!MTB"
        threat_id = "2147949373"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f 93 c0 0f b6 c0 48 c1 e0 04 48 8d 0d ?? ?? ?? ?? 48 8b 04 08 48 b9 [0-8] 48 01 c8 ff e0 48 8b 44 24 48 48 8b 4c 24 60 48 89 ca 48 83 c2 01 48 89 54 24 60 8a 09 88 08 48 8b 44 24 48 48 83 c0 01 48 89 44 24 48 48 8b 44 24 40 48 83 c0 01 48 89 44 24 40}  //weight: 2, accuracy: Low
        $x_1_2 = "f_u_c_k......" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_PAFZ_2147949537_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.PAFZ!MTB"
        threat_id = "2147949537"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8b 44 24 30 3b 84 24 0c 02 00 00 7d ?? 8b 44 24 30 99 f7 7c 24 64 48 63 c2 0f be 84 04 66 02 00 00 48 8b 8c 24 00 02 00 00 48 63 54 24 30 44 0f b6 04 11 41 31 c0 44 88 04 11 8b 44 24 30 83 c0 01 89 44 24 30 eb}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_PCW_2147949659_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.PCW!MTB"
        threat_id = "2147949659"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Could get Payload from resource" ascii //weight: 1
        $x_1_2 = "Could not get Beacon from (local) resource" ascii //weight: 1
        $x_1_3 = "BEACON_RESOURCE" ascii //weight: 1
        $x_1_4 = "Ran CobaltStrike" ascii //weight: 1
        $x_1_5 = "ReverseShell_%s_%s.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_UGA_2147953143_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.UGA!MTB"
        threat_id = "2147953143"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 d2 44 29 ca 41 89 d2 48 63 d2 44 0f b6 0c 14 46 88 0c 1c 88 0c 14 42 02 0c 1c 0f b6 c9 0f b6 14 0c 42 32 14 06 42 88 14 03 49 83 c0 ?? 4c 39 c7 75 a3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_SYB_2147953204_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.SYB!MTB"
        threat_id = "2147953204"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 8b 0a 48 85 c9 74 ?? 4b 8d 04 18 43 0f b6 1c 1f 48 89 c2 48 09 ca 48 c1 ea ?? 74 ?? 31 d2 48 f7 f1 48 89 d1 48 83 f9 ?? 72}  //weight: 1, accuracy: Low
        $x_1_2 = {89 d1 48 83 f9 ?? 73 ?? 41 32 1c 09 43 88 5c 1d ?? 49 ff c3 4d 39 dc 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_PSW_2147953205_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.PSW!MTB"
        threat_id = "2147953205"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b9 1a 00 00 00 48 89 d3 f3 ab 48 8d 7c 24 50 b9 06 00 00 00 31 d2 f3 ab}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_SSG_2147953699_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.SSG!MTB"
        threat_id = "2147953699"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {42 31 04 09 49 83 c1 04 8b 83 ?? 00 00 00 01 83 ?? 00 00 00 8b 43 10 29 83 ?? 00 00 00 8b 83 ?? 00 00 00 05 ba c5 1a 00 31 83 b4 00 00 00 49 81 f9 f4 e1 01 00 7c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_NKC_2147953774_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.NKC!MTB"
        threat_id = "2147953774"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "decrypt successful!" ascii //weight: 2
        $x_1_2 = "aLdbcGgcd@hdf;iff9igf5jgg/khg)khg" ascii //weight: 1
        $x_1_3 = "bWebdRgceNhdfHjehAjfh<lhi9lij6mij/njk(njk" ascii //weight: 1
        $x_1_4 = "fbdXhdeSiegOjfhGlhiAmij<mik9okl5okl.plm'qll!rnn" ascii //weight: 1
        $x_1_5 = "alfccahdfZjfhUkgjOmijHnklBqmm>qmn:rno6soo.sop'tpp!wsr" ascii //weight: 1
        $x_1_6 = "ebaxgcdnjfhckgi[lhjUmikPokmIplnBqmo>snp;toq7tpq" ascii //weight: 1
        $x_1_7 = "njlVokmQrnoHsoqCtpq?uqr;vqr5vrs-wrs&xtu!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_NWU_2147954063_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.NWU!MTB"
        threat_id = "2147954063"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c1 48 8b 45 ?? ba ?? ?? ?? ?? 48 f7 75 ?? 48 8b 45 ?? 48 01 d0 0f b6 00 31 c1 48 8b 55 ?? 48 8b 45 ?? 48 01 d0 89 ca 88 10 48 83 45 ?? ?? 48 8b 45 ?? 48 3b 45 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_NWU_2147954063_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.NWU!MTB"
        threat_id = "2147954063"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Tchoupi\\x64\\Release\\Tchoupi.pdb" ascii //weight: 1
        $x_1_2 = "Add ExclusionPath" ascii //weight: 1
        $x_1_3 = "\\Microsoft\\Windows\\Defender" ascii //weight: 1
        $x_1_4 = "WinExec" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_GVN_2147955213_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.GVN!MTB"
        threat_id = "2147955213"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 89 e5 48 83 ec 20 b9 e8 03 00 00 48 8b 05 b2 9c 06 00 ff d0}  //weight: 2, accuracy: High
        $x_1_2 = {48 8b 05 ec 9b 06 00 ff d0 48 89 45 f8 b9 fa 00 00 00 48 8b 05 22 9c 06 00 ff d0 b9 fa 00 00 00 48 8b 05 14 9c 06 00 ff d0 eb 07}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_GVP_2147955344_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.GVP!MTB"
        threat_id = "2147955344"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {3a 2f 2f 33 38 2e 31 39 30 2e 32 32 34 2e 36 33 3a 38 38 2f [0-16] 2e 65 78 65}  //weight: 3, accuracy: Low
        $x_1_2 = "InternetOpenUrlA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_GVO_2147955713_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.GVO!MTB"
        threat_id = "2147955713"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {33 f6 66 41 89 34 1e 0f 57 c0 0f 11 45 ff f3 0f 7f 75 0f c6 45 ff 00 48 8d 5d df 4c 8b 4d df 4c 8b 5d f7 49 83 fb 07 49 0f 47 d9 48 8d 4d df 49 0f 47 c9 48 8b 45 ef 48 8d 3c 41 48 3b df 74 25}  //weight: 2, accuracy: High
        $x_1_2 = {6b c9 21 41 03 c8 44 0f be 02 48 8d 52 01 45 85 c0 75 ed}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_RR_2147955865_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.RR!MTB"
        threat_id = "2147955865"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 84 24 80 00 00 00 7c c6 84 24 81 00 00 00 72 c6 84 24 82 00 00 00 65 c6 84 24 83 00 00 00 79 c6 84 24 84 00 00 00 72 c6 84 24 85 00 00 00 7b c6 84 24 86 00 00 00 24 c6 84 24 87 00 00 00 25 c6 84 24 88 00 00 00 39 c6 84 24 89 00 00 00 73 c6 84 24 8a 00 00 00 7b c6 84 24 8b 00 00 00 7b c6 84 24 8c 00 00 00 17}  //weight: 1, accuracy: High
        $x_1_2 = "DllSafeCheck64" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_AHD_2147956516_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.AHD!MTB"
        threat_id = "2147956516"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {09 ca 8b b4 24 b1 02 00 00 48 c1 e2 ?? 48 c1 e6 ?? 48 09 d6 4c 8b bc 24 b8 02 00 00 4c 8b ac 24 c0 02 00 00 48 09 c6}  //weight: 30, accuracy: Low
        $x_20_2 = {66 0f 10 84 24 20 01 00 00 66 41 0f 11 04 36 49 ff c5 4c 89 ac 24 d0 00 00 00 48 83 c6}  //weight: 20, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_WH_2147958378_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.WH!MTB"
        threat_id = "2147958378"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 55 10 48 8b 45 f8 48 01 d0 0f b6 10 48 8b 4d 10 48 8b 45 f8 48 01 c8 83 f2 ?? 88 10 48 83 45 f8 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_SRA_2147958653_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.SRA!MTB"
        threat_id = "2147958653"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 54 d5 00 4c 01 f2 4f 8d 04 40 49 83 c0 06 48 83 f1 03 45 31 d2 45 31 db 48 be 93 2d 59 57 18 77 87 0e 49 39 f1 41 0f 93 c2 4e 8d 14 95 04 00 00 00 41 0f 95 c3 4e 8d 1c 9d 07 00 00 00 31 f6 4d 39 f9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_NW_2147958944_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.NW!MTB"
        threat_id = "2147958944"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 15 3a 1c 00 00 89 d2 41 89 c0 48 8d 05 2e 1a 00 00 48 89 c1 e8 66 fe ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrike_GDZ_2147959260_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrike.GDZ!MTB"
        threat_id = "2147959260"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 c9 48 63 f8 48 8b d7 41 b8 00 30 00 00 48 03 d2 44 8d 49 ?? ff 15}  //weight: 5, accuracy: Low
        $x_5_2 = {8b 45 a7 33 c8 89 4d a7 b9 ?? ?? ?? ?? 8b 45 a7 89 75 a7}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

