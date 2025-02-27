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

