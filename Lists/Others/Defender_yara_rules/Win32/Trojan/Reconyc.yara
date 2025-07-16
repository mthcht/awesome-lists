rule Trojan_Win32_Reconyc_2147808929_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Reconyc.dwuq!MTB"
        threat_id = "2147808929"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Reconyc"
        severity = "Critical"
        info = "dwuq: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 e1 83 ea 01 52 ff 0c 24 5a c1 ea 05 c1 ea 08 81 e2 ?? ?? ?? ?? 81 f2 ?? ?? ?? ?? 89 d1 89 c8}  //weight: 10, accuracy: Low
        $x_2_2 = "TJprojMain.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Reconyc_DA_2147809083_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Reconyc.DA!MTB"
        threat_id = "2147809083"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Reconyc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WinLicenseDriverVersion" ascii //weight: 1
        $x_1_2 = "EVENT_SINK_GetIDsOfNames" ascii //weight: 1
        $x_1_3 = "TJprojMain.exe" ascii //weight: 1
        $x_1_4 = "myapp.exe" ascii //weight: 1
        $x_1_5 = "Project1" ascii //weight: 1
        $x_1_6 = "Themida" ascii //weight: 1
        $x_1_7 = ".taggant" ascii //weight: 1
        $x_1_8 = "i.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Reconyc_HMP_2147809223_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Reconyc.HMP!MTB"
        threat_id = "2147809223"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Reconyc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 45 d0 be ?? ?? ?? ?? 81 f6 ?? ?? ?? ?? 2b 35 ?? ?? ?? ?? 83 f6 ?? 81 c6 ?? ?? ?? ?? 2b 75 ?? 33 f0 03 35 ?? ?? ?? ?? 89 75}  //weight: 10, accuracy: Low
        $x_1_2 = ".polyphaH" ascii //weight: 1
        $x_1_3 = ".dumps" ascii //weight: 1
        $x_1_4 = ".erotoge" ascii //weight: 1
        $x_1_5 = ".noncate" ascii //weight: 1
        $x_1_6 = ".finkel" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Reconyc_CE_2147814126_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Reconyc.CE!MTB"
        threat_id = "2147814126"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Reconyc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff 75 28 8d 45 f0 ff 75 24 ff 75 20 ff 75 1c ff 75 18 ff 75 14 ff 75 10 ff 75 0c 50}  //weight: 1, accuracy: High
        $x_1_2 = {51 ff 75 1c 56 53 ff 75 10 ff 75 0c}  //weight: 1, accuracy: High
        $x_1_3 = "C:\\windows\\system32\\Fun1.dll" ascii //weight: 1
        $x_1_4 = "IsDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Reconyc_BD_2147836032_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Reconyc.BD!MTB"
        threat_id = "2147836032"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Reconyc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 fc 8b 55 f8 8a 5c 10 ff 80 f3 0a 8d 45 f4 8b d3 e8 [0-4] 8b 55 f4 8b c7 e8 [0-4] ff 45 f8 4e 75}  //weight: 2, accuracy: Low
        $x_1_2 = "CreateMutexA" ascii //weight: 1
        $x_1_3 = "ResumeThread" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Reconyc_MA_2147844366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Reconyc.MA!MTB"
        threat_id = "2147844366"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Reconyc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {53 56 29 c9 89 8d f0 fe ff ff 8b da 50 5e 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 53 58 e8 ?? ?? ?? ?? 8d 45 fc 50 56 6a 00 e8}  //weight: 5, accuracy: Low
        $x_5_2 = {ff 25 d0 c1 44 00 8b c0 ff 25 48 c2 44 00 8b c0 ff 25 44 c2 44 00 8b c0 ff 25 40 c2 44 00 8b c0 ff 25 cc c1 44 00 8b c0 ff 25 c8 c1 44 00 8b c0 ff 25 58 c2 44 00 8b c0 ff 25 54}  //weight: 5, accuracy: High
        $x_5_3 = {dc b5 44 00 89 01 89 0d dc b5 44 00 29 d2 8b c2 03 c0 8d 44 c1 04 8b 1e 89 18 89 06 42 83 fa 64 75 ec 8b 06 8b 10 89 16 5e 5b c3 90 89 00 89 40}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Reconyc_GXZ_2147903460_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Reconyc.GXZ!MTB"
        threat_id = "2147903460"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Reconyc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {01 f8 0f b6 c0 29 f8 8b bc 85 ?? ?? ?? ?? 89 bc 95 ?? ?? ?? ?? 89 8c 85 ?? ?? ?? ?? 03 8c 95 ?? ?? ?? ?? 89 cf c1 ff ?? c1 ef ?? 01 f9 0f b6 c9 29 f9 8b 8c 8d ?? ?? ?? ?? 8b 7d ?? 32 0c 37 8b bd ?? ?? ?? ?? 88 0c 37 83 c6 ?? 39 de}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Reconyc_GNT_2147929907_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Reconyc.GNT!MTB"
        threat_id = "2147929907"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Reconyc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {ff 34 1a 40 00 c0 54 40 00 10 93 40 00 10}  //weight: 10, accuracy: High
        $x_1_2 = "\\guodongguodong.guodong" ascii //weight: 1
        $x_1_3 = "\\svchest.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Reconyc_GVB_2147946570_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Reconyc.GVB!MTB"
        threat_id = "2147946570"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Reconyc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {96 8e fd 44 dd a1 8a f3 5a e5 b6 07 02 3c 25 83 ae ec 78 b5 de a7 07 0d d2 15 82 dd 02 63 a3 b5 7a 7f d9 0f 9a 51 72 0d 3e 5b 89 e4 64 ce 6c 2d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

