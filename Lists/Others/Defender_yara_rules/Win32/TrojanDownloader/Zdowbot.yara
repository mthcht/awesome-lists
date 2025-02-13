rule TrojanDownloader_Win32_Zdowbot_A_2147712227_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zdowbot.A"
        threat_id = "2147712227"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zdowbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 cd cc cc cc f7 e1 c1 ea 03 8d 04 92 03 c0 8b d1 2b d0 8a 82 ?? ?? ?? 00 30 04 39 41 3b ce 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zdowbot_A_2147712227_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zdowbot.A"
        threat_id = "2147712227"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zdowbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 44 24 13 76 c7 44 24 1c 40 00 00 00 c7 44 24 14 71 00 00 00 bf 7e 00 00 00 c7 44 24 20 15 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b d5 6b d2 76 b8 91 73 9f 5d f7 e2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zdowbot_A_2147712227_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zdowbot.A"
        threat_id = "2147712227"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zdowbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f 67 61 74 65 2e 70 68 70 7c 68 74 74 70 3a 2f 2f [0-32] 2e 72 75 2f [0-6] 2f 67 61 74 65 2e 70 68 70 7c 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_2 = {2f 6c 73 35 2f 66 6f 72 75 6d 2e 70 68 70 7c 68 74 74 70 3a 2f 2f [0-32] 2e 72 75 2f [0-6] 2f 66 6f 72 75 6d 2e 70 68 70 7c 68 74 74 70 3a 2f 2f [0-32] 2e 72 75 2f 01 2f 66 6f 72 75 6d 2e 70 68 70}  //weight: 1, accuracy: Low
        $x_2_3 = "GUID=%I64u&BUILD=%s&INFO=%s&IP=%s&TYPE=1&WIN=%d.%d(%s)" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Zdowbot_B_2147712445_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zdowbot.B"
        threat_id = "2147712445"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zdowbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 67 66 66 66 f7 e9 c1 fa 02 8b c2 c1 e8 1f 03 c2 8d 04 80 03 c0 8b d1 2b d0 8a 82 ?? ?? ?? 00 30 04 0e 41 3b 0d ?? ?? ?? 00 72 ce}  //weight: 1, accuracy: Low
        $x_1_2 = {b8 67 66 66 66 f7 e9 c1 fa 02 8b c2 c1 e8 1f 03 c2 8b 15 ?? ?? ?? 00 8d 04 80 03 c0 2b d0 8a 04 0a 30 04 0e 41 3b 0d ?? ?? ?? 00 76 cd}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_Win32_Zdowbot_ARA_2147835012_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zdowbot.ARA!MTB"
        threat_id = "2147835012"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zdowbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 45 f8 99 b9 0a 00 00 00 f7 f9 a1 00 40 40 00 0f be 0c 10 8b 15 40 40 40 00 03 55 f8 0f be 02 33 c1 8b 0d 40 40 40 00 03 4d f8 88 01 eb b1}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zdowbot_ARA_2147835012_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zdowbot.ARA!MTB"
        threat_id = "2147835012"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zdowbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {83 fe ff 74 2f 6a 00 6a 00 ff d7 8b 0d 50 60 40 00 b8 67 66 66 66 f7 ee c1 fa 02 8b c2 c1 e8 1f 03 c2 8d 14 80 a1 00 60 40 00 03 d2 2b c2 8a 14 30 30 14 31 46 3b 35 5c 60 40 00 72 c3}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zdowbot_ARA_2147835012_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zdowbot.ARA!MTB"
        threat_id = "2147835012"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zdowbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {83 fe ff 74 33 6a 00 6a 00 6a 00 6a 00 ff d7 8b 0d 2c 40 40 00 b8 67 66 66 66 f7 ee c1 fa 02 8b c2 c1 e8 1f 03 c2 8d 14 80 a1 00 40 40 00 03 d2 2b c2 8a 14 30 30 14 31 46 3b 35 38 40 40 00 72 bf 5f 5e 5b c3 cc cc cc 53 56 57 eb 73 e8 22 0d}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zdowbot_ARAC_2147839813_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zdowbot.ARAC!MTB"
        threat_id = "2147839813"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zdowbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {83 f9 ff 74 29 8b 35 50 80 40 00 b8 67 66 66 66 f7 e9 c1 fa 02 8b c2 c1 e8 1f 03 c2 8d 14 80 03 d2 8b c1 2b c2 8a 90 dc 71 40 00 30 14 0e 41 3b 0d 5c 80 40 00 72 c9 5f 5e c3 cc cc cc 81 ec 2c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zdowbot_ARAE_2147846654_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zdowbot.ARAE!MTB"
        threat_id = "2147846654"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zdowbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {83 fe ff 74 2f 6a 00 6a 00 ff d7 8b 0d ?? ?? ?? ?? b8 ?? ?? ?? ?? f7 ee c1 fa 02 8b c2 c1 e8 1f 03 c2 8d 14 80 a1 ?? ?? ?? ?? 03 d2 2b c2 8a 14 30 30 14 31 46 3b 35 ?? ?? ?? ?? 72 c3}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Zdowbot_ARAD_2147899490_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zdowbot.ARAD!MTB"
        threat_id = "2147899490"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zdowbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {85 c9 7c 29 8b 35 88 ec 40 00 b8 67 66 66 66 f7 e9 c1 fa 02 8b c2 c1 e8 1f 03 c2 8d 04 80 03 c0 8b d1 2b d0 8a 82 48 b3 40 00 30 04 0e 41 3b 0d 94 ec 40 00 72 ca}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

