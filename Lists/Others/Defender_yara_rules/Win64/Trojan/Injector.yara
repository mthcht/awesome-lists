rule Trojan_Win64_Injector_CD_2147731260_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Injector.CD"
        threat_id = "2147731260"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 0f b6 ca 45 0f b6 c2 41 8d 41 fc 48 63 d0 0f b6 04 0a 41 30 04 08 45 8d 41 01 41 8d 41 fd 48 63 d0 0f b6 04 0a 41 30 04 08 41 8d 41 fe 48 63 d0 45 8d 41 02 0f b6 04 0a 41 30 04 08 41 8d 41 ff 48 63 d0 45 8d 41 03 0f b6 04 0a 41 30 04 08 41 80 c2 fc 75 aa}  //weight: 1, accuracy: High
        $x_1_2 = {0f b6 17 48 8b 5c 24 08 0f b6 c2 24 01 f6 d8 0f b6 41 1d 45 1a c0 d0 ea 41 80 e0 8d 44 32 c2 42 0f b6 14 18 0f b6 41 1e 41 32 d0 30 11 44 88 07 48 8b 7c 24 10 42 0f b6 04 18 30 41 01 0f b6 41 1f 42 0f b6 04 18 30 41 02 0f b6 41 1c 42 0f b6 04 18 30 41 03 c3}  //weight: 1, accuracy: High
        $x_1_3 = {48 89 5c 24 08 44 0f b6 02 48 8d 1d ?? ?? ?? ?? 0f b6 41 1d 4c 8d 59 04 4c 8b ca 41 b2 04 0f b6 04 18 41 32 c0 30 01 0f b6 41 1e 0f b6 04 18 30 41 01 0f b6 41 1f 0f b6 04 18 30 41 02 0f b6 41 1c 0f b6 04 18 30 41 03 41 0f b6 c0 c0 e8 07 45 02 c0 0f b6 c0 6b d0 1b 41 32 d0 41 88 11 66}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Injector_GPKL_2147927074_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Injector.GPKL!MTB"
        threat_id = "2147927074"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c8 44 8b ca 0f 1f 40 00 6b c9 21 4d 8d 40 01 41 33 c9 45 0f be 48 ff 45 85 c9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Injector_LM_2147946819_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Injector.LM!MTB"
        threat_id = "2147946819"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {41 0f b6 09 41 ff c0 83 e1 0f 4a 0f be 84 31 60 ad 76 00 42 8a ?? ?? ?? ?? ?? ?? 4c 2b c8 41 8b 51 fc d3 ea ff ca 45 3b c3}  //weight: 10, accuracy: Low
        $x_15_2 = {4a 0f be 84 19 60 ad 76 00 42 8a ?? ?? ?? ?? ?? ?? 48 2b d0 8b 42 fc 4c 8d 42 04 d3 e8 49 89 51 08 41 89 41 20 8b 02 4d 89 41 08 41 89 41 24 49 83 ea 01}  //weight: 15, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Injector_KK_2147948308_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Injector.KK!MTB"
        threat_id = "2147948308"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {8a 94 04 8e 00 00 00 89 d7 40 f6 df 19 c9 83 e1 44 31 ca 41 88 14 02 48 ff c0 48 83 f8 12}  //weight: 20, accuracy: High
        $x_10_2 = {0f b7 c0 49 ff c3 31 d0 c1 ea 10 69 c0 3b 9f 5d 04 31 c2}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Injector_KK_2147948308_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Injector.KK!MTB"
        threat_id = "2147948308"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {48 33 c1 48 8b d0 8b c0 48 c1 ea ?? 48 33 d0 41 83 e0 ?? 48 8b c2 49 33 c1 41 be ?? 00 00 00 48 35 ?? ?? ?? ?? 41 8b ce 48 c1 e8 08 41 2a c8 48 33 c2}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Injector_NM_2147951188_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Injector.NM!MTB"
        threat_id = "2147951188"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 8d 0d 42 e5 09 00 bf 01 00 00 00 ?? b8 e0 f9 ff 48 85 db 76 5c 48 89 44 ?? 28 48 c7 44 ?? 20 00 00 00 00 48 8b 54 ?? 28 48 89 54 ?? 20 48 8b 05 ac 83 1a 00 48 8d 5c ?? 20 b9 01 00 00 00 48 89 cf ?? e2 76 fb ff 66}  //weight: 2, accuracy: Low
        $x_1_2 = {48 8d 05 62 f4 08 00 66 ?? ?? 3b 08 f6 ff 48 8b 8c ?? a8 00 00 00 48 89 48 08 48 8b 8c ?? b0 00 00 00 48 89 48 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Injector_AHJ_2147951991_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Injector.AHJ!MTB"
        threat_id = "2147951991"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {48 63 8d c4 fe ff ff 48 8b d1 48 c1 e2 08 48 03 d1 0f b7 8d c4 fe ff ff 48 33 ca 48 33 c8}  //weight: 10, accuracy: High
        $x_30_2 = {48 03 d0 48 63 85 1c ff ff ff 48 03 d0 48 63 85 18 ff ff ff 48 03 d0 48 03 95 10 ff ff ff 48 33 95 28 ff ff ff 48 87 11 48}  //weight: 30, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Injector_PGIN_2147954056_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Injector.PGIN!MTB"
        threat_id = "2147954056"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {50 61 79 6c 6f 61 64 20 63 6f 70 69 65 64 20 74 6f 20 6c 6f 63 61 6c 20 6d 61 70 70 69 6e 67 3a 20 30 78 25 70 0a}  //weight: 2, accuracy: High
        $x_2_2 = {53 65 63 74 69 6f 6e 20 6d 61 70 70 65 64 20 69 6e 74 6f 20 72 65 6d 6f 74 65 20 70 72 6f 63 65 73 73 20 61 74 3a 20 30 78 25 70 0a}  //weight: 2, accuracy: High
        $x_1_3 = "Injection completed successfully!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Injector_NA_2147954600_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Injector.NA!MTB"
        threat_id = "2147954600"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 8b 72 08 33 ff 4c 03 ce 45 33 c0 8b d5 41 0f b6 09 83 e1 0f 4a 0f be 84 31 48 2c 03 00 42 8a 8c 31 58 2c 03 00 4c 2b c8 45 8b 59 fc 41 d3 eb 45 85 db 74 6c}  //weight: 2, accuracy: High
        $x_1_2 = {41 0f b6 09 41 ff c0 83 e1 0f 4a 0f be 84 31 48 2c 03 00 42 8a 8c 31 58 2c 03 00 4c 2b c8 41 8b 51 fc d3 ea ff ca 45 3b c3 72 a5 45 85 c0 0f 44 d5 8b c2 eb 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Injector_SXA_2147956727_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Injector.SXA!MTB"
        threat_id = "2147956727"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "Low"
    strings:
        $x_15_1 = {ff c0 48 98 48 c7 44 24 ?? ?? ?? ?? ?? 4c 8b c8 4c 8d 45 50 48 8b 95 d8 01 00 00 48 8b 8d b8 01 00 00 ff 15}  //weight: 15, accuracy: Low
        $x_10_2 = {48 6b c0 01 48 8b 8d 18 04 00 00 48 8b 04 01 48 89 45 08 b8 ?? ?? ?? ?? 48 6b c0 ?? 48 8b 8d 18 04 00 00 48 8b 04 01}  //weight: 10, accuracy: Low
        $x_1_3 = "DLL Inject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Injector_SXB_2147957469_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Injector.SXB!MTB"
        threat_id = "2147957469"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 8b 44 24 38 0f b7 40 14 48 8b 4c 24 38 48 8d 44 01 18 48 63 4c 24 30 48 6b c9 ?? 48 03 c1 48 89 44 24 48}  //weight: 10, accuracy: Low
        $x_1_2 = "Injected sucessfully" ascii //weight: 1
        $x_1_3 = "AgentService.exe" ascii //weight: 1
        $x_1_4 = "Hook detect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Injector_LMB_2147957708_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Injector.LMB!MTB"
        threat_id = "2147957708"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {48 63 44 24 24 33 d2 b9 10 00 00 00 48 f7 f1 48 8b c2 0f be 44 04 7c 48 63 4c 24 24 48 8b 54 24 58 0f b6 0c 0a 33 c8 8b c1 48 63 4c 24 24 48 8b 54 24 58 88 04 0a}  //weight: 20, accuracy: High
        $x_10_2 = {48 8b 4c 24 40 48 03 c8 48 8b c1 48 89 44 24 58 c7 44 24 24 00 00 00 00 eb ?? 8b 44 24 24 ff c0 89 44 24 24 48 8b 44 24 30 8b 40 10 39 44 24 24}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Injector_SXC_2147958668_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Injector.SXC!MTB"
        threat_id = "2147958668"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_15_1 = {48 89 44 24 68 c5 fe 6f 44 24 50 c5 fd ef 4c 24 30 c5 fe 7f 4c 24 30 c5 f8 77}  //weight: 15, accuracy: High
        $x_10_2 = {48 8b 44 24 20 48 89 44 24 48 48 89 4c 24 20 48 8d 4c 24 30 48 8b 44 24 20 48 89 54 24 20 33 d2 48 89 44 24 50 48 8b 44 24 20 4c 89 44 24 20 48 89 44 24 58}  //weight: 10, accuracy: High
        $x_1_3 = "chrome" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Injector_SXD_2147959940_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Injector.SXD!MTB"
        threat_id = "2147959940"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {44 32 d6 41 fe c2 c1 64 24 08 ?? 41 80 f2 86 48 c7 44 24 00 ?? ?? ?? ?? 41 d0 ca 48 c1 74 24 08 ?? 66 81 6c 24 01 ?? ?? 48 c1 4c 24 07 ?? 41 80 f2 32 48 ff 44 24 08 c1 7c 24 0b}  //weight: 20, accuracy: Low
        $x_10_2 = {41 fe cb 41 32 f3 f7 5c 24 ?? 48 c1 4c 24 ?? ?? 4e 8d 5c 1c ?? 41 88 0b 0f 99 44 24 ?? 48 8d 64 24}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Injector_AMTB_2147960766_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Injector!AMTB"
        threat_id = "2147960766"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RtlAdjustPrivilege" ascii //weight: 1
        $x_1_2 = "NtRaiseHardError" ascii //weight: 1
        $x_1_3 = "lsass.exe" ascii //weight: 1
        $x_1_4 = "NtQueryVirtualMemory" ascii //weight: 1
        $x_1_5 = "NtQuerySystemInformation" ascii //weight: 1
        $x_1_6 = "QWNjZWxNb2RlID0gMApTZW5zaXRpdml0eSA9IDEuMwpBY2NlbGVyYXRpb24gPSAw" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Injector_SXE_2147961408_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Injector.SXE!MTB"
        threat_id = "2147961408"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {49 8b d4 49 8b cf ff 15 ?? ?? ?? ?? 85 c0 0f 84 ?? ?? ?? ?? 48 39 7d e8 0f 85 ?? ?? ?? ?? 4c 89 6c 24 30 44 89 6c 24 28 4c 89 64 24 20 4c 8b 0d ?? ?? ?? ?? 45 33 c0 33 d2 49 8b cf ff 15 ?? ?? ?? ?? 48 8b d8 48 85 c0}  //weight: 30, accuracy: Low
        $x_10_2 = "Successfully injected" ascii //weight: 10
        $x_10_3 = "bypass anti-cheat hook" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Injector_AHM_2147961742_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Injector.AHM!MTB"
        threat_id = "2147961742"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {48 63 d0 48 8b 45 20 48 01 d0 44 89 c2 31 ca 88 10 83 45 fc ?? 8b 45 fc 48 98 48 3b 45 28 72}  //weight: 30, accuracy: Low
        $x_20_2 = {0f b6 45 c7 c1 e0 ?? 89 c2 0f b6 45 c6 09 d0 89 c2 48 8b 45 10 89 10 e9}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Injector_PGAD_2147963583_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Injector.PGAD!MTB"
        threat_id = "2147963583"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\injector.dll" ascii //weight: 1
        $x_1_2 = "//10.148.0.8:8000/injector.bin" ascii //weight: 1
        $x_1_3 = "win_update_service.exe" ascii //weight: 1
        $x_1_4 = "cmd.exe /c curl -s -L \"" ascii //weight: 1
        $x_1_5 = {44 4c 4c 20 49 4e 4a 45 43 54 49 4f 4e 20 53 55 43 43 45 53 53 46 [0-3] 4c 4c 59 21}  //weight: 1, accuracy: Low
        $x_1_6 = "log.txt" ascii //weight: 1
        $x_1_7 = "notepad.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Injector_PGAD_2147963583_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Injector.PGAD!MTB"
        threat_id = "2147963583"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\\\Boot\\memtest.exe" ascii //weight: 1
        $x_1_2 = "Full Delphi Virus/Worm made By FuTuRaX" ascii //weight: 1
        $x_1_3 = "C:\\\\Bat00100.bat" ascii //weight: 1
        $x_1_4 = "FACEHACKER" ascii //weight: 1
        $x_1_5 = "software\\microsoft\\windows\\currentversion\\run" ascii //weight: 1
        $x_1_6 = "C:\\\\WINDOWS\\ServicePackFiles\\i386\\lang\\tintsetp.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Injector_SXF_2147964948_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Injector.SXF!MTB"
        threat_id = "2147964948"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {48 83 c2 70 45 33 ed 4c 89 6c 24 20 41 b9 08 00 00 00 4c 8d 85 b8 00 00 00 48 8b 0d ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 48 c1 eb 20 48 89 9d}  //weight: 20, accuracy: Low
        $x_5_2 = "Injected" ascii //weight: 5
        $x_1_3 = "RobloxPlayerBeta.exe" ascii //weight: 1
        $x_1_4 = "Waiting for hook" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Injector_SXG_2147965214_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Injector.SXG!MTB"
        threat_id = "2147965214"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {45 0f b7 02 8d 48 ?? 66 83 f9 19 8d 50 ?? 66 0f 47 d0 41 8d 40 ?? 66 83 f8 19 41 8d 48 ?? 66 41 0f 47 c8 66 3b d1 ?? ?? 41 0f b7 41 ?? 49 83 c1 02 49 83 c2 02 66 85 c0}  //weight: 30, accuracy: Low
        $x_10_2 = {46 0f b6 44 0c 40 49 8b c9 48 8b c6 49 f7 e1 48 c1 ea 03 48 6b c2 0f 48 2b c8 0f b6 0c 29 48 03 cb 49 03 c8 0f b6 d9 0f b6 44 1c 40 42 88 44 0c 40 49 ff c1 44 88 44 1c 40 49 81 f9 00 01 00 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Injector_SXH_2147965730_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Injector.SXH!MTB"
        threat_id = "2147965730"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c7 44 24 20 40 00 00 00 44 8b 46 50 48 8b 56 30 ff 15 ?? ?? ?? ?? 4c 8b f8 48 85 c0 75 07 33 ff ?? ?? ?? ?? ?? 44 8b 4e 54 45 33 ed 48 8b 4c 24 50 4c 8b c3 49 8b d7 4c 89 6c 24 20 ff 15 ?? ?? ?? ?? 85 c0}  //weight: 10, accuracy: Low
        $x_5_2 = "Target process is 32-bit: %s" ascii //weight: 5
        $x_20_3 = "C:\\Users\\%s\\AppData\\Local\\Temp\\scoped_dir" ascii //weight: 20
        $x_5_4 = "Source32: %s, Target32: %s" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Injector_SXI_2147967066_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Injector.SXI!MTB"
        threat_id = "2147967066"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "High"
    strings:
        $x_30_1 = "Attempt to inject into browser process" ascii //weight: 30
        $x_20_2 = "InfectorDLL" ascii //weight: 20
        $x_10_3 = "This would require native messaging or other injection methods" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Injector_SXJ_2147967263_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Injector.SXJ!MTB"
        threat_id = "2147967263"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "High"
    strings:
        $x_30_1 = {c7 44 24 40 71 77 65 61 c7 44 24 44 73 64 33 32 c7 44 24 48 31 7a 78 63 c6 44 24 4c 00 48 c7 45 b8 0f 00 00 00}  //weight: 30, accuracy: High
        $x_20_2 = {c7 44 24 60 57 72 69 74 c7 44 24 64 65 50 72 6f c7 44 24 68 63 65 73 73 c7 44 24 6c 4d 65 6d 6f 66 c7 44 24 70 72 79}  //weight: 20, accuracy: High
        $x_10_3 = {0f b6 0c 13 88 0a 48 ff c2 48 8d 0c 17 8b 85 60 01 00 00 48 3b c8 72 e8}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Injector_ARR_2147967501_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Injector.ARR!MTB"
        threat_id = "2147967501"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 89 44 24 ?? f3 0f 6f 0c 33 f3 0f 6f 44 1c ?? 0f 55 ce 0f 57 c8 f3 0f 7f 0c 33 48 83 c3}  //weight: 10, accuracy: Low
        $x_4_2 = {44 8b c0 4c 89 44 24 ?? 41 8b 44 24 ?? 41 8b ce 48 03 c2 41 83 c6 ?? 0f b7 14 01 0f b7 ca 66 3b d7}  //weight: 4, accuracy: Low
        $x_6_3 = {41 8b 44 24 ?? 48 03 c2 45 8b ce 4c 03 c8 41 83 c6 ?? 4c 89 4d 88 41 8b 41 04 48 83 e8 ?? 48 d1 e8 85 c0}  //weight: 6, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Injector_MK_2147967634_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Injector.MK!MTB"
        threat_id = "2147967634"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {44 8b 43 14 41 8b c8 41 8b c0 48 c1 e8 1e 83 e0 01 48 c1 e9 1d 83 e1 01 48 8d 0c 48 41 8b c0 48 c1 e8 1f 48 8d 0c 48 41 8b c0 44 8b 54 8d 00 41 0f ba ea 09 25 ?? ?? ?? ?? 8b 03 44 0f 44 54 8d 00 8b c8}  //weight: 30, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Injector_SXK_2147967725_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Injector.SXK!MTB"
        threat_id = "2147967725"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_30_1 = {48 8b 44 24 28 31 c9 48 2b 4c 24 08 48 01 c8 48 8b 4c 24 18 0f b6 04 08 48 8b 4c 24 30 48 8b 54 24 18 0f b6 0c 11}  //weight: 30, accuracy: High
        $x_20_2 = {48 01 c8 8b 48 08 48 8b 44 24 50 89 08 48 8b 44 24 48 48 8b 4c 24 30 48 63 54 24 2c 48 6b d2 28 48 01 d1}  //weight: 20, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Injector_SXL_2147967930_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Injector.SXL!MTB"
        threat_id = "2147967930"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "56"
        strings_accuracy = "High"
    strings:
        $x_30_1 = "Succsesfully injected" ascii //weight: 30
        $x_15_2 = "[-] DLL not placed. Exiting loader..." ascii //weight: 15
        $x_5_3 = "sideloadingdll" ascii //weight: 5
        $x_5_4 = "eac injector" ascii //weight: 5
        $x_1_5 = "CLSID\\{4B770032-31CA-43B1-AB0D-32C5FE2F82FA}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

