rule Trojan_Win32_Yogi_A_2147979773_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Yogi.A!MTB"
        threat_id = "2147979773"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Yogi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {83 bd bc fd ff ff 07 8d 85 a8 fd ff ff 68 0c 52 00 10 0f 47 85 a8 fd ff ff 50 8d 85 a4 fd ff ff c7 85 a4 fd ff ff 00 00 00 00 50 ff 15 ?? ?? ?? ?? 83 c4 0c 85 c0}  //weight: 20, accuracy: Low
        $x_10_2 = {66 0f 13 85 74 fe ff ff 0f 11 85 7c fe ff ff c7 85 48 ff ff ff 00 00 00 00 0f 11 85 38 ff ff ff c7 85 4c ff ff ff 00 00 00 00 e8 ?? ?? ?? ?? 83 bd 1c ff ff ff 07 8d 85 08 ff ff ff ff b5 18 ff ff ff 0f 47 85 08 ff ff ff 8d 8d 38 ff ff ff}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Yogi_B_2147980746_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Yogi.B!MTB"
        threat_id = "2147980746"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Yogi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ba 33 00 00 00 66 89 55 ea b8 65 00 00 00 66 89 45 ec b9 32 00 00 00 66 89 4d ee ba 39 00 00 00 66 89 55 f0 b8 62 00 00 00 66 89 45 f2 b9 31 00 00 00 66 89 4d f4 ba 39 00 00 00 66 89 55 f6 33 c0 66 89 45 f8 68 03 00 1f 00 6a 02 8d 4d c8 51 6a 00 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Yogi_AB_2147982291_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Yogi.AB!MTB"
        threat_id = "2147982291"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Yogi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {8a 0c 3a 8a 45 e8 32 c3 32 c1 88 04 3a 0f b6 c1 8a 4c 3a 01 03 d8 8b c3 c1 e8 08 32 45 e4 32 c1 88 44 3a 01 0f b6 c1 8a 4c 3a 02 03 d8 8b c3 c1 e8 10 32 45 e0 32 c1 88 44 3a 02 0f b6 c1 8a 4c 3a 03 03 d8 8b c3 c1 e8 18 32 45 dc 32 c1 88 44 3a 03 83 c2 04 0f b6 c1 03 d8 83 ee 01 75 a1}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Yogi_C_2147982305_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Yogi.C!MTB"
        threat_id = "2147982305"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Yogi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {89 65 e8 89 4d 88 c7 01 00 00 00 00 c7 45 dc 42 79 40 56 c6 45 e0 3c}  //weight: 20, accuracy: High
        $x_10_2 = {8b 4d 94 03 cb 8d 55 dc 8b 01 3b 02 0f 85 ?? ?? ?? ?? 0f b6 41 04 3a 42 04}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Yogi_2147982854_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Yogi!atmn"
        threat_id = "2147982854"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Yogi"
        severity = "Critical"
        info = "atmn: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Failed to allocate XMRig payload buffer." ascii //weight: 3
        $x_3_2 = "Failed to allocate WildRig payload buffer." ascii //weight: 3
        $x_3_3 = "\"mining_url\": \"stratum+tcp://rvn.2miners.com:16060\"," ascii //weight: 3
        $x_1_4 = "\"wallet\": \"RWZ66gYzdqfdpzGnQP5o8HjVwDjmKHWHP1\"," ascii //weight: 1
        $x_1_5 = "\"wallet\": \"46pZ7PWeGSnjNq6iY3QnpNKL5E7B3S2ixjQngjMu5RiPJQkPiPdLyH8h1YTsty6ZqDE4qVtGYkWs8Y9auPnsEL1QGECSbK5\"," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

