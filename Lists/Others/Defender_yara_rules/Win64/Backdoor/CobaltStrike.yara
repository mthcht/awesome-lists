rule Backdoor_Win64_CobaltStrike_MYK_2147784057_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/CobaltStrike.MYK!MTB"
        threat_id = "2147784057"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 f7 29 fa 89 d7 81 c7 [0-4] 0f bf ff 69 ff [0-4] c1 ef 10 01 d7 81 c7 00 21 cf 89 fe c1 ee 0f c1 ef 06 01 f7 89 fe c1 e6 07 29 f7 01 fa 81 c2 00 88 54 04 20 48 ff c0 48 83 f8 [0-1] 75}  //weight: 1, accuracy: Low
        $x_1_2 = {01 fa 81 c2 [0-4] 0f bf d2 69 d2 [0-4] c1 ea 10 01 f2 83 c2 [0-1] 21 ca 89 d7 c1 ef 0f c1 ea 06 01 fa 89 d7 c1 e7 07 29 fa 01 f2 83 c2 02 88 54 04 20 48 ff c0 48 83 f8 [0-1] 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Backdoor_Win64_CobaltStrike_AA_2147787524_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/CobaltStrike.AA!MTB"
        threat_id = "2147787524"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {55 48 89 e5 48 83 ec 50 c7 45 e4 ?? ?? ?? ?? 8b 05 ?? 2a 03 00 89 c0 41 b9 ?? ?? ?? ?? 4c 8d 05 ?? ?? 03 00 48 89 c2 48 8d 0d ?? 29 03 00 e8 ?? ff ff ff 48 8d 0d ?? ?? 03 00 48 8b 05 ?? ?? 03}  //weight: 10, accuracy: Low
        $x_10_2 = {55 48 89 e5 48 83 ec 10 48 89 4d 10 48 89 55 18 4c 89 45 20 4c 89 4d 28 c7 45 fc}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_CobaltStrike_UID_2147799068_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/CobaltStrike.UID!dha"
        threat_id = "2147799068"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "90909090-9090-5a4d-4152-554889e54881" ascii //weight: 1
        $x_1_2 = "90909090-9090-9090-904d-5a4152554889" ascii //weight: 1
        $x_1_3 = "4d909090-415a-5552-4889-e54881ec2000" ascii //weight: 1
        $x_1_4 = "a5c9b7c3-fa82-b6d4-c7cf-c728c1e7384b" ascii //weight: 1
        $x_1_5 = "2b0c483c-83bd-c3c3-4800-28d82b4a773c" ascii //weight: 1
        $x_1_6 = "000020ec-4800-1d8d-eaff-ffff4889df48" ascii //weight: 1
        $x_1_7 = "2e2e2e2e-2e2e-2e2e-2e2e-2e2e2e2e2e2e" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Win64_CobaltStrike_MAK_2147805251_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/CobaltStrike.MAK!MTB"
        threat_id = "2147805251"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 3b c6 0f b6 04 28 41 88 42 ff 72 50 00 b8 [0-4] 41 8b c8 47 88 04 11 49 83 c2 01 41 f7 e0 2b ca 41 8b c0 d1 e9 41 83 c0 01 03 ca c1 e9 [0-1] 6b c9 [0-1] 2b c1}  //weight: 1, accuracy: Low
        $x_1_2 = {45 0f b6 01 43 0f be 0c 0b b8 [0-4] 03 cf 49 83 c1 01 41 03 c8 8b f9 f7 e1 c1 ea [0-1] 69 d2 [0-4] 2b fa 48 83 ee 01 48 63 cf 0f b6 04 19 41 88 41 ff 44 88 04 19 75}  //weight: 1, accuracy: Low
        $x_1_3 = {83 c3 01 b8 [0-4] 45 8b c3 45 2b c5 41 83 c3 01 f7 e3 c1 ea [0-1] b8 [0-4] 69 d2 [0-4] 2b da 4c 63 d3 45 0f b6 0c 3a 45 03 e1 41 f7 e4 c1 ea [0-1] 69 d2 [0-4] 44 2b e2 49 63 cc 0f b6 04 39 41 88 04 3a 44 88 0c 39 41 0f b6 0c 3a 41 03 c9 b8 [0-4] f7 e1 c1 ea [0-1] 69 d2 [0-4] 2b ca 48 63 c1 0f b6 0c 38 41 30 0c 30 48 83 ed 01 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Backdoor_Win64_CobaltStrike_MCK_2147808362_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/CobaltStrike.MCK!MTB"
        threat_id = "2147808362"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c9 49 63 d2 49 3b d1 4d 8d 5b 01 48 0f 45 ce 42 0f b6 04 01 48 8d 71 01 41 30 43 ff 33 c0 49 3b d1 41 0f 45 c2 ff c3 44 8d 50 01 48 63 c3 48 3b c7 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

