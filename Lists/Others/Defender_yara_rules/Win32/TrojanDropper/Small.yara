rule TrojanDropper_Win32_Small_ALH_2147574434_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Small.ALH"
        threat_id = "2147574434"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "autolive.sys" ascii //weight: 1
        $x_1_2 = "Software\\Microsoft\\SSearch" ascii //weight: 1
        $x_1_3 = "%s\\Rundll32.exe \"%s\\%s\",DllCanUnloadNow" ascii //weight: 1
        $x_1_4 = "regsvr32 /u /s %s\\InteSearch.dll" ascii //weight: 1
        $x_1_5 = "Software\\Microsoft\\SSearch\\Update" ascii //weight: 1
        $x_1_6 = "system32\\drivers\\%s.sys" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDropper_Win32_Small_OT_2147593294_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Small.OT"
        threat_id = "2147593294"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 85 c0 fe ff ff 40 89 85 c0 fe ff ff 8b 85 c0 fe ff ff 3b 45 e4 73 3b 8b 85 c0 fe ff ff 69 c0 ?? ?? ?? ?? 0f af 85 c0 fe ff ff 8b 8d c0 fe ff ff 69 c9 ?? ?? ?? ?? 03 c8 8b 45 e8 03 85 c0 fe ff ff 8a 00 32 c1 8b 4d e8 03 8d c0 fe ff ff 88 01 eb ad ff 75 e8 e8 ?? ?? ?? ?? 59 89 85 c4 fe ff ff 83 bd c4 fe ff ff 00 75 04 33 c0 eb 4b 68 ?? ?? ?? ?? ff b5 c4 fe ff ff e8 ?? ?? ?? ?? 59 59}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Small_DAN_2147600179_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Small.DAN"
        threat_id = "2147600179"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 04 01 00 00 8d 85 30 fd ff ff 50 ff 15 6c 10 40 00 68 e0 10 40 00 8d 8d 30 fd ff ff 51 ff 15 68 10 40 00 6a ?? 68 ?? ?? ?? 00 68 00 ?? 00 00 68 ?? ?? ?? 00 8d 95 30 fd ff ff 52 e8 f4 fc ff ff 83 c4 14 8d 85 30 fd ff ff 50 e8 e5 fe ff ff 83 c4 04 68 60 ea 00 00 ff 15 64 10 40 00 83 7d dc 01 0f 85 3a 01 00 00 e8 88 03 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {68 04 01 00 00 8d 8d 30 fd ff ff 51 ff 15 6c 10 40 00 68 f0 10 40 00 8d 95 30 fd ff ff 52 ff 15 68 10 40 00 6a ?? 68 ?? ?? ?? 00 68 00 ?? 00 00 68 ?? ?? ?? 00 8d 85 30 fd ff ff 50 e8 87 fc ff ff}  //weight: 1, accuracy: Low
        $x_1_3 = "winmsdn.exe" ascii //weight: 1
        $x_1_4 = "dllcache\\fuurod.sys" ascii //weight: 1
        $x_1_5 = "drivers\\beep.sys" ascii //weight: 1
        $x_1_6 = "dllcache\\beep.sys" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Small_NBV_2147601054_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Small.NBV"
        threat_id = "2147601054"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "105"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {68 4c 10 40 00 53 ff 15 ?? ?? ?? ?? 53 ff 15 ?? ?? ?? ?? 6a 05 6a 00 6a 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 00 ff 15 ?? ?? ?? ?? 6a 00 ff 15}  //weight: 100, accuracy: Low
        $x_5_2 = "C:\\X-STARS.exe" ascii //weight: 5
        $x_5_3 = "c:\\ntlcs.exe" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Small_NBW_2147601148_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Small.NBW"
        threat_id = "2147601148"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "C:\\TEMP\\" ascii //weight: 1
        $x_1_2 = "eh34tg" ascii //weight: 1
        $x_1_3 = {6a 00 68 80 00 00 00 6a 03 6a 00 6a 01 68 00 00 00 80 ff 75 10 ff 15 ?? ?? ?? ?? 89 45 f4 6a 00 68 80 00 00 00 6a 02 6a 00 6a 02 68 00 00 00 40 ff 75 14 ff 15 ?? ?? ?? ?? 89 45 fc 83 7d f4 ff 74 06 83 7d fc ff 75 07 32 c0 e9 ?? ?? ?? ?? 6a 00 6a 00 ff 75 08 ff 75 f4 ff 15 ?? ?? ?? ?? 83 65 f0 00 83 7d 0c 00 0f 86 ?? ?? ?? ?? 81 7d 0c 00 40 00 00 72 ?? 6a 00 8d 45 f8 50 68 00 40 00 00 ff 75 ec ff 75 f4 ff 15 ?? ?? ?? ?? 83 65 e4 00 eb 07 8b 45 e4 40 89 45 e4 8b 45 e4 3b 45 f8}  //weight: 1, accuracy: Low
        $x_1_4 = {0f b7 c0 99 6a 05 59 f7 f9 83 c2 07 52 8d 85 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 8d 84 05 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 59 59 68 ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? 50 ff 15}  //weight: 1, accuracy: Low
        $x_1_5 = {be f4 10 40 00 8d bd a0 fc ff ff a5 66 a5 a4 33 c0 8d bd a7 fc ff ff aa 68 fc 10 40 00 8d 85 a0 fc ff ff 50 ff 15 ?? ?? ?? ?? 8d 45 c4 50 ff 15 ?? ?? ?? ?? 85 c0 74 2e 6a 40 ff 75 fc ff 15 ?? ?? ?? ?? 6a 01 ff 75 fc ff 15 ?? ?? ?? ?? 6a 00 8d 85 b0 fd ff ff 50 6a 05 6a 04 ff 15 ?? ?? ?? ?? 33 c0 40 eb 20 6a 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Small_NBX_2147606749_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Small.NBX"
        threat_id = "2147606749"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c9 8d 85 fd fe ff ff 38 8d fc fe ff ff 74 07 8a 10 40 84 d2 75 f9 48 6a 01 c6 00 5c 88 48 01 8d 85 fc fe ff ff 50 ff 75 14 ff 75 08 68 ?? ?? ?? ?? 51 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 44 8e e8 89 44 8f e8 8b 44 8e ec 89 44 8f ec 8b 44 8e f0 89 44 8f f0 8b 44 8e f4 89 44 8f f4 8b 44 8e f8 89 44 8f f8 8b 44 8e fc 89 44 8f fc 8d 04 8d 00 00 00 00 03 f0 03 f8 ff 24 95 ?? ?? 00 10}  //weight: 1, accuracy: Low
        $x_1_3 = {83 c6 03 83 c7 03 83 f9 08 72 cc f3 a5 ff 24 95 ?? ?? 00 10 8d 49 00 23 d1 8a 06 88 07 8a 46 01 c1 e9 02 88 47 01 83 c6 02 83 c7 02 83 f9 08 72 a6 f3 a5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Small_AJS_2147607790_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Small.AJS"
        threat_id = "2147607790"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff 53 f8 40 74 46 48 86 e4 50 56 6a 00 54 86 e4 83 2c 24 50 55 57 86 f6 50 ff 53 e4 5e 9b ff 53 f4 8b 54 24 04 86 f6 8b 04 24 6a 01 6a 00 6a 00 50 6a 00 9b 6a 00 ff d2 86 e4 03 fd 90 57 ff 53 e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Small_FI_2147609558_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Small.FI"
        threat_id = "2147609558"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "32"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {81 3c 31 50 45 00 00 0f ?? ?? 00 00 00}  //weight: 10, accuracy: Low
        $x_10_2 = {5c 5c 2e 5c c7 85 ?? ?? ?? ?? 50 68 79 73}  //weight: 10, accuracy: Low
        $x_10_3 = {6f 6e 64 2e c7 ?? ?? 65 78 65 00}  //weight: 10, accuracy: Low
        $x_1_4 = "CreateRemoteThread" ascii //weight: 1
        $x_1_5 = "WriteProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Small_N_2147616874_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Small.gen!N"
        threat_id = "2147616874"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 45 fc 56 05 00 0a 00 00}  //weight: 10, accuracy: High
        $x_10_2 = {56 50 8d 85 10 6b fb ff 68 00 0e 00 00 50 ff 75 f8}  //weight: 10, accuracy: High
        $x_10_3 = {56 50 bb 0e cb 00 00 8d 85 10 6b fb ff 53 50}  //weight: 10, accuracy: High
        $x_1_4 = "book.exe" ascii //weight: 1
        $x_1_5 = "book.pdf" ascii //weight: 1
        $x_1_6 = "AcroRd32.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Small_PM_2147624761_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Small.PM"
        threat_id = "2147624761"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {32 33 20 2d 20 36 36 36 00}  //weight: 1, accuracy: High
        $x_1_2 = {b8 01 00 00 00 85 c0 74 30 6a 0a ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 00 ff 15 ?? ?? ?? ?? 89 45 fc}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 55 08 03 55 fc 8a 02 2c ?? 8b 4d 08 03 4d fc 88 01 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Small_DK_2147832932_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Small.DK!MTB"
        threat_id = "2147832932"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {80 2f 47 80 37 15 80 37 47 f6 17 47 e2}  //weight: 2, accuracy: High
        $x_1_2 = "C:\\TEMP\\a2008.exe" wide //weight: 1
        $x_1_3 = "Couldn't get IsDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Small_ARA_2147896555_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Small.ARA!MTB"
        threat_id = "2147896555"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {73 18 0f b6 84 24 bc 00 00 00 30 02 89 f8 42 03 84 24 bd 00 00 00 39 c2 eb e6}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Small_PABT_2147897556_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Small.PABT!MTB"
        threat_id = "2147897556"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 08 03 45 fc 0f b6 08 83 f1 18 8b 55 08 03 55 fc 88 0a 8b 45 0c 83 e8 01 89 45 0c 8b 4d fc 83 c1 01 89 4d fc 83 7d 0c 00 75 d4}  //weight: 1, accuracy: High
        $x_1_2 = {8b 55 08 03 55 fc 0f be 02 33 45 0c 8b 4d f4 03 4d fc 88 01 8b 55 fc 83 c2 01 89 55 fc 8b 45 f0 89 45 ec 8b 4d f0 83 e9 01 89 4d f0 83 7d ec 00 75 ce}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Small_PACT_2147900200_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Small.PACT!MTB"
        threat_id = "2147900200"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 46 04 8a c8 80 e1 01 0f b6 7e 05 fe c9 f6 d9 1b c9 24 08 2c 08 41 f6 d8 89 4c 24 18 1b c0 40 89 44 24 10 0f b6 46 06 c1 e7 08 03 f8 0f b6 46 07 c1 e7 08 03 f8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Small_PACV_2147900201_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Small.PACV!MTB"
        threat_id = "2147900201"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {85 f6 5f 5b 74 1e 90 0f b6 11 33 d0 81 e2 ff 00 00 00 c1 e8 08 33 04 95 68 ed 41 00 83 c1 01 83 ee 01 75 e3}  //weight: 1, accuracy: High
        $x_1_2 = "Infected" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Small_HNS_2147904415_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Small.HNS!MTB"
        threat_id = "2147904415"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 73 0b 0f b6 02 42 34 ?? 88 01 41 eb ed}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

