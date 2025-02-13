rule Trojan_Win32_AveMariaRat_MB_2147796705_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMariaRat.MB!MTB"
        threat_id = "2147796705"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMariaRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b ac 24 18 04 00 00 41 81 e1 ff 00 00 80 79 08 49 81 c9 00 ff ff ff 41 8b 7c 8c 14 03 f7 81 e6 ff 00 00 80 79 08 4e 81 ce 00 ff ff ff 46 8a 5c 8c 14 8b 7c b4 14 88 5c 24 10 89 7c 8c 14 8b 7c 24 10 81 e7 ff 00 00 00 89 7c b4 14 8b 5c 8c 14 03 df 81 e3 ff 00 00 80 79 08 4b 81 cb 00 ff ff ff 43 8a 5c 9c 14 30 1c 2a 42 3b d0 72}  //weight: 1, accuracy: High
        $x_1_2 = {8b f8 85 f6 89 7d 0c 76 19 8b 45 08 8b cf 2b c7 89 75 08 8a 14 08 88 11 8b 55 08 41 4a 89 55 08 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AveMariaRat_MD_2147807607_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMariaRat.MD!MTB"
        threat_id = "2147807607"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMariaRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vejgkguic" ascii //weight: 1
        $x_1_2 = "rweayzzu.dll" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\heartbreaker" ascii //weight: 1
        $x_1_4 = "cobra\\embarrasses\\fractures.jpg" ascii //weight: 1
        $x_1_5 = "IsProcessorFeaturePresent" ascii //weight: 1
        $x_1_6 = "Sleep" ascii //weight: 1
        $x_1_7 = "WriteFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AveMariaRat_MH_2147811770_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMariaRat.MH!MTB"
        threat_id = "2147811770"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMariaRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c1 01 89 4d 00 8b 55 fc 83 ea 01 39 55 00 7f ?? 8b 45 fc 83 e8 01 2b 45 00 8b 4d dc 8b 14 81 f7 d2 89 55 e8 83 7d e8 00 74 ?? 8b 45 f8 03 45 00 8a 4d e8 88 08 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 55 0c 8a 0c 0a 88 4c 05 08 ba 01 00 00 00 c1 e2 00 b8 01 00 00 00 c1 e0 00 8b 4d 0c 8a 14 11 88 54 05 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AveMariaRat_MI_2147811771_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMariaRat.MI!MTB"
        threat_id = "2147811771"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMariaRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 07 33 d2 88 44 24 10 b9 ?? ?? ?? ?? 8a 47 01 88 44 24 11 8a 47 02 88 44 24 12 8a 47 03 88 44 24 13 c7 07 ?? ?? ?? ?? 8b 01 f7 d0 85 c0 74 ?? 88 04 2a 83 e9 04 42 81 f9 ?? ?? ?? ?? 7d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AveMariaRat_MM_2147813149_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMariaRat.MM!MTB"
        threat_id = "2147813149"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMariaRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4d 88 83 c1 01 89 4d 88 8b 55 84 83 ea 01 39 55 88 7f 33 8b 45 84 83 e8 01 2b 45 88 8b 8d 64 ff ff ff 8b 14 81 f7 d2 89 95 70 ff ff ff 83 bd 70 ff ff ff 00 74 0e 8b 45 80 03 45 88 8a 8d 70 ff ff ff 88 08 eb b9}  //weight: 1, accuracy: High
        $x_1_2 = {b8 01 00 00 00 6b c8 00 ba 01 00 00 00 6b c2 00 8b 55 94 8a 0c 0a 88 4c 05 90 ba 01 00 00 00 c1 e2 00 b8 01 00 00 00 c1 e0 00 8b 4d 94 8a 14 11 88 54 05 90 b8 01 00 00 00 d1 e0 b9 01 00 00 00 d1 e1 8b 55 94 8a 04 02 88 44 0d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AveMariaRat_MS_2147814892_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMariaRat.MS!MTB"
        threat_id = "2147814892"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMariaRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f0 14 78 38 f7 be 70 16 37 b8 3e 75 b0 f0 41 cc 1a 71 10 32 7b fb b9 60 15 3d 6e bf 43 10 34 62 dc 30 b1 fb 4c 3e 75 7e bb 37 3d 80 36 39 82 c1 1f f5 41 d6 bd f7 6f 69 4f 32 bb f8 cf f7 47 3b 07 f5 74 f1 b8 7e 12 31 bf 6d 10 3d bb 37 bc 37 72 7a b6 f4 44 cf b3 70 13 30 fb f9 fb fa f9 fe 05 30 27 38 31 4a 3c c1 ec 35 f0 bb f4 36 b0 38}  //weight: 1, accuracy: High
        $x_1_2 = {a1 88 58 41 00 89 45 d8 8b 0d ?? ?? ?? ?? 89 4d dc 8b 15 ?? ?? ?? ?? 89 55 e0 66 a1 ?? ?? ?? ?? 66 89 45 e4 8a 0d ?? ?? ?? ?? 88 4d e6 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AveMariaRat_2147815840_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMariaRat.MT!MTB"
        threat_id = "2147815840"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMariaRat"
        severity = "Critical"
        info = "MT: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 51 ff 15 ?? ?? ?? ?? 89 c3 6a 00 50 ff 15 30 00 c6 84 10 ?? ?? ?? ?? ?? 42 75 ?? 6a 00 68 80 00 00 00 6a 03 6a 00 6a 07 68 00 00 00 80}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AveMariaRat_MU_2147815842_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMariaRat.MU!MTB"
        threat_id = "2147815842"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMariaRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 64 59 f7 f1 8b 4d 8c 8a 44 15 98 30 04 0f 47 81 ff 00 e8 03 00 7c}  //weight: 1, accuracy: High
        $x_1_2 = "CreateMutexW" ascii //weight: 1
        $x_1_3 = "RaiseException" ascii //weight: 1
        $x_1_4 = "CreateRemoteThread" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AveMariaRat_MV_2147816211_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMariaRat.MV!MTB"
        threat_id = "2147816211"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMariaRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0c 8a 0c 0a 88 4c 05 08 ?? 01 00 00 00 c1 ?? 00 ?? 01 00 00 00 c1 ?? 00 8b ?? 0c 8a 14 11 88 54 05 08 ?? 01 00 00 00 d1 [0-5] b9 01 00 00 00 d1 ?? 8b ?? 0c 8a 04 02 88 44 0d 08 ?? 01 00 00 00 6b ?? 03 ?? 01 00 00 00 6b ?? 03 8b ?? 0c 8a 14 10 88 54 0d 08}  //weight: 1, accuracy: Low
        $x_1_2 = "CreateThread" ascii //weight: 1
        $x_1_3 = "LockResource" ascii //weight: 1
        $x_1_4 = "IsDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AveMariaRat_MW_2147816786_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMariaRat.MW!MTB"
        threat_id = "2147816786"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMariaRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c9 41 6b c9 00 8b 55 94 8a 04 02 88 44 0d ?? 33 c0 40 c1 e0 00 33 c9 41 c1 e1 00 8b 55 94 8a 04 02 88 44 0d ?? 33 c0 40 d1 e0 33 c9 41 d1 e1 8b 55 94 8a 04 02 88 44}  //weight: 1, accuracy: Low
        $x_1_2 = "Sleep" ascii //weight: 1
        $x_1_3 = "ResumeThread" ascii //weight: 1
        $x_1_4 = "WriteProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AveMariaRat_MX_2147817477_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMariaRat.MX!MTB"
        threat_id = "2147817477"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMariaRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 c0 40 d1 e0 33 c9 41 d1 e1 8b 55 ?? 8a 04 02 88 44 0d ?? 33 c0 40 6b c0 ?? 33 c9 41 6b c9 ?? 8b 55 ?? 8a 04 02 88 44 0d ?? 33 c0 40 6b c0 ?? 8b 4d ?? c6 04 01 ?? 33 c0 40 c1 e0 ?? 8b 4d ?? c6 04 01 ?? 33 c0 40 d1 e0 8b 4d 0c c6 04 01 00 33 c0 40 6b c0 ?? 8b 4d ?? c6 04 01 ?? 83 65 [0-5] eb}  //weight: 5, accuracy: Low
        $x_1_2 = "NtDelayExecution" ascii //weight: 1
        $x_1_3 = "IsProcessorFeaturePresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AveMariaRat_MZ_2147817553_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMariaRat.MZ!MTB"
        threat_id = "2147817553"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMariaRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 c0 40 6b c0 ?? 33 c9 41 6b c9 ?? 8b 55 ?? 8a 04 02 88 44 0d ?? 33 c0 40 6b c0 ?? 8b 4d ?? c6 04 01 ?? 33 c0 40 c1 e0 00 8b 4d ?? c6 04 01 ?? 33 c0 40 d1 e0 8b 4d 94 c6 04 01 ?? 33 c0 40 6b c0 ?? 8b 4d ?? c6 04 01 ?? 83 65 ?? ?? eb}  //weight: 2, accuracy: Low
        $x_1_2 = "Wow64GetThreadContext" ascii //weight: 1
        $x_1_3 = "IsProcessorFeaturePresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AveMariaRat_MAA_2147823175_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AveMariaRat.MAA!MTB"
        threat_id = "2147823175"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AveMariaRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 f7 bd 6c ff ff ff 89 95 5c ff ff ff 81 7d ?? ?? ?? ?? ?? 74 ?? 8b 4d 80 03 4d ?? 0f be 11 8b 85 5c ff ff ff 0f be 4c 05 98 33 d1 8b 45 80 03 45 ?? 88 10 eb}  //weight: 1, accuracy: Low
        $x_1_2 = "FindFirstFileExW" ascii //weight: 1
        $x_1_3 = "ReadProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

