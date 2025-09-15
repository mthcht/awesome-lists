rule Trojan_Win32_FakeAV_AG_2147819838_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeAV.AG!MTB"
        threat_id = "2147819838"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeAV"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "bcdedit.exe -set" ascii //weight: 2
        $x_2_2 = "ZSTSIGNING ON" ascii //weight: 2
        $x_2_3 = "JSDA.EXE" wide //weight: 2
        $x_2_4 = "Pro23ctVersion" wide //weight: 2
        $x_2_5 = "W_ aH" ascii //weight: 2
        $x_2_6 = "D7togE" ascii //weight: 2
        $x_2_7 = "hutdownPtil" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FakeAV_AK_2147896090_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeAV.AK!MTB"
        threat_id = "2147896090"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeAV"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Dump of offset" ascii //weight: 1
        $x_1_2 = "EIP=" ascii //weight: 1
        $x_1_3 = "EFL=" ascii //weight: 1
        $x_1_4 = "WriteConsoleOutputCharacterA" ascii //weight: 1
        $x_1_5 = "WriteConsoleOutputAttribute" ascii //weight: 1
        $x_1_6 = "FlushConsoleInputBuffer" ascii //weight: 1
        $x_1_7 = "0C0M0S0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FakeAV_ARAA_2147906264_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeAV.ARAA!MTB"
        threat_id = "2147906264"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeAV"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {83 f9 00 74 0a 8a 06 32 c3 88 06 46 49 eb f1}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FakeAV_NF_2147917703_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeAV.NF!MTB"
        threat_id = "2147917703"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeAV"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8d 95 cc f9 ff ff 8b 45 ec 01 d0 88 08 83 6d f4 02 83 45 f0 01 83 45 ec 01 eb ?? 8b 45 f0 8b 55 d0}  //weight: 3, accuracy: Low
        $x_2_2 = {83 7d f4 00 7e ?? 8b 45 ec 01 c0 0f b6 84 05 cc fb ff ff 0f be c0 c1 e0 04 89 c2 8b 45 ec}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FakeAV_ASGT_2147919811_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeAV.ASGT!MTB"
        threat_id = "2147919811"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeAV"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {83 ec 10 56 57 68 ?? ?? ?? 00 6a 00 8d 44 24 14 6a 01 50 c7 44 24 1c 0c 00 00 00 c7 44 24 20 00 00 00 00 c7 44 24 24 00 00 00 00 ff 15 ?? ?? ?? 00 8b 0d ?? ?? ?? 00 8b f0 51 ff 15 ?? ?? ?? 00 8d 54 24 08 c7 44 24 08 00 00 00 00}  //weight: 3, accuracy: Low
        $x_2_2 = {55 8b ec 83 ec 10 53 56 57 a0 ?? ?? 66 00 32 05 ?? ?? 66 00 a2 ?? ?? 66 00 33 c9 8a 0d ?? ?? 66 00 c1 f9 03 83 c9 01 89 4d f0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FakeAV_GPN_2147928973_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeAV.GPN!MTB"
        threat_id = "2147928973"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeAV"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 81 ec 80 04 00 00 53 56 57 89 95 80 fb ff ff 89 8d 84 fb ff ff c7 45 fc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FakeAV_AFK_2147936583_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeAV.AFK!MTB"
        threat_id = "2147936583"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeAV"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 85 7c ff ff ff 00 8b 55 fc 89 95 78 ff ff ff 8b 85 78 ff ff ff 03 45 8c 8a 08 88 8d 7c ff ff ff 8a 95 7c ff ff ff 02 55 c0 88 95 7c ff ff ff 6a 01 8d 85 7c ff ff ff 50 8b 8d 78 ff ff ff 03 4d 8c 51}  //weight: 1, accuracy: High
        $x_2_2 = {8b 4d f4 89 4d a8 8b 55 c8 83 c2 01 89 55 c8 8b 45 c8 6b c0 03 89 45 b8 8b 4d a8 89 4d c4 8b 55 c4 03 55 ac 89 55 c4 8b 45 a0 50 8b 4d a8 03 4d ac 51 8b 55 fc 52}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FakeAV_AFV_2147936688_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeAV.AFV!MTB"
        threat_id = "2147936688"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeAV"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8a d0 c0 c2 04 8a c2 24 0f bb 01 60 40 00 d7 a2 91 6b 40 00 c0 c2 04 8a c2 24 0f d7 a2 92 6b 40 00}  //weight: 3, accuracy: High
        $x_2_2 = {ba 00 00 00 00 f7 f3 92 e8 ?? ?? ?? ?? 88 87 b0 67 40 00 4f 92 41 0b c0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FakeAV_NA_2147940056_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeAV.NA!MTB"
        threat_id = "2147940056"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeAV"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 45 d8 21 45 f4 81 45 dc}  //weight: 2, accuracy: High
        $x_1_2 = {8b 45 f0 31 45 f4 8b 45 0c 21}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FakeAV_MX_2147952275_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeAV.MX!MTB"
        threat_id = "2147952275"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeAV"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "JUMP@@YIKKK@Z" ascii //weight: 1
        $x_1_2 = "wsmt5.exe" ascii //weight: 1
        $x_1_3 = "Xbl@YcmAZdnB[eoC" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

