rule Trojan_Win32_ValleyRAT_EC_2147913492_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ValleyRAT.EC!MTB"
        threat_id = "2147913492"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ValleyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b c6 83 e0 0f 8a 04 08 30 04 16 46 3b f3 72 f0}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ValleyRAT_DA_2147947212_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ValleyRAT.DA!MTB"
        threat_id = "2147947212"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ValleyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {db 1a ce 30 48 be e2 93 0f 67 60 c1 1b 4b 9f 6f 14 1a 4d df cc 64 38 e2 55 28 8d 3f 8c 0b f1 c3 65 f6 03 8c d1 1d 86 ad 52 c7 88 19 bd 8c 8d 94 b5 b7 35 c4 59 3e 79 32 11 dc 84 3a f3 df 90 e9 74 74 40 bb 8d d1 36 f1 4a 79 53 93 ca}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ValleyRAT_DA_2147947212_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ValleyRAT.DA!MTB"
        threat_id = "2147947212"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ValleyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 5e d8 eb 32 8a f4 9a 3c f5 68 9a 19 a9 7e 25 93 ad 1e a2 56 6b 67 8c aa 16 b1 3f 8f 65 b6 64 48 1b 39 dd d1 85 ce 5e a1 01 e4 76 b6 0e a2 99 55 7b 2a 69 12 48 c1 4f d4 94 6d 26 78 a3 0a 17 59 b8 21 84 8f 24 7b 4f c5 4a 24 6b 87 0b 78 69 56 5e 41 17 38 6c b2 48 55 73 2d a3 22 cf 0a 81 db 28 9c c7 84 0c 37 aa 65 96 6a 77 bf 97 07 a0 47 ec 48 59 d4 3a 81 cd 8a 34 06 ac 94 7e d5 0e b3 7f 66 9a 5e 36 d0 26 9f}  //weight: 1, accuracy: High
        $x_1_2 = {6f 4c 5c 8a 97 ec 73 a7 c8 06 9b 16 36 39 71 92 3d 12 e9 ec 34 9a 06 67 41 8d e2 e9 b4 c0 0a 8f 6e 1d 6a db e1 c7 ac 2b 94 e3 a1 c3 8a 4c 1b 08 5a 8c ed 49 88 c7 45 51 df 2e 5f 8c c1 86 12 f0 72 77 86 68 06 ee 2e e3 27 a8 8b 47 0a 69 7a 0e 2c 6e 86 a7 2a b0 fd b7 91 0d cc c1 6c 9c 38 44 28 53}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_ValleyRAT_PAHL_2147949159_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ValleyRAT.PAHL!MTB"
        threat_id = "2147949159"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ValleyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "monitor.bat" ascii //weight: 2
        $x_2_2 = "tasklist /FI \"IMAGENAME eq %ProcessName%\" | findstr /I \"%ProcessName%\" >nul" ascii //weight: 2
        $x_1_3 = "cmd.exe /B /c \"%s\"" ascii //weight: 1
        $x_1_4 = "monitor.pid" ascii //weight: 1
        $x_1_5 = "copy /Y \"%BackupProcessPath%\" \"%ProcessPath%\"" ascii //weight: 1
        $x_1_6 = "INVALID.aps" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ValleyRAT_GBVL_2147950691_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ValleyRAT.GBVL!MTB"
        threat_id = "2147950691"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ValleyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 c0 01 89 85 ?? ?? ?? ?? 83 bd ?? ?? ?? ?? ?? 73 ?? 8b 8d ?? ?? ?? ?? 0f be 54 0d ?? 81 f2 91 00 00 00 8b 85 ?? ?? ?? ?? 88 54 05}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ValleyRAT_NW_2147958155_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ValleyRAT.NW!MTB"
        threat_id = "2147958155"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ValleyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 04 07 47 99 f7 f9 8b 46 08 8b 4d 10 80 c2 36 89 7d 08 32 14 08 88 14 01 b8 64 1d 00 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ValleyRAT_AHB_2147959548_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ValleyRAT.AHB!MTB"
        threat_id = "2147959548"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ValleyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "mzy.dat" ascii //weight: 10
        $x_20_2 = "OpeeProcdssaoken" ascii //weight: 20
        $x_30_3 = {f7 f1 0f b7 1c 55 ?? ?? ?? ?? e8 ?? ?? ?? ?? 4f 75 ?? 8b c6 8b 4d f4}  //weight: 30, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ValleyRAT_ABV_2147961126_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ValleyRAT.ABV!MTB"
        threat_id = "2147961126"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ValleyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {68 74 74 70 3a 2f 2f 31 30 33 2e 31 32 31 2e 39 33 2e 37 38 3a 32 33 32 33 2f [0-15] 2e 62 69 6e}  //weight: 5, accuracy: Low
        $x_1_2 = "schtasks /create /tn \"%s\" /tr \"\"%s\"\" /sc onlogon /rl highest" ascii //weight: 1
        $x_1_3 = "CreatePersistentTask called" ascii //weight: 1
        $x_1_4 = "Cleaning up memory" ascii //weight: 1
        $x_1_5 = "Delaying execution" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ValleyRAT_GHT_2147961985_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ValleyRAT.GHT!MTB"
        threat_id = "2147961985"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ValleyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {56 8b f1 57 6a 40 68 00 30 00 00 8b 46 04 2b 06 50 6a 00 ff 15 ?? ?? ?? ?? 8b f8 85 ff ?? ?? 8b 16 8b 4e 04 2b ca 51 52 57 e8 ?? ?? ?? ?? 83 c4 0c 6a 00 6a 00 6a 00 57 6a 00 6a 00 ff 15 ?? ?? ?? ?? 85 c0 74 09 6a ff 50 ff 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ValleyRAT_PGVR_2147962707_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ValleyRAT.PGVR!MTB"
        threat_id = "2147962707"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ValleyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {0f 57 84 24 a0 00 00 00 0f 29 84 24 a0 00 00 00 0f 28 84 24 50 02 00 00 0f 57 84 24 b0 00 00 00 0f 29 84 24 b0 00 00 00 0f 28 84 24 30 03 00 00 0f 57 84 24 c0 00 00 00 0f 29 84 24 c0 00 00 00 0f 28 44 24 40 0f 57 84 24 d0 00 00 00 0f 29 84 24 d0 00 00 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ValleyRAT_AHA_2147967925_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ValleyRAT.AHA!MTB"
        threat_id = "2147967925"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ValleyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_40_1 = "e5b6ebe2bd1f6b7045bc74f32a72e14bb78b" ascii //weight: 40
        $x_30_2 = "bdbc1e81bf8b79b6dcd496e814853965" ascii //weight: 30
        $x_20_3 = "nThumbnailExtractionHost.exe" ascii //weight: 20
        $x_10_4 = "ZhiMaUpdate.dll" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ValleyRAT_SX_2147969442_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ValleyRAT.SX!MTB"
        threat_id = "2147969442"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ValleyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_30_1 = {8b c1 33 d2 f7 75 e8 8b 4d e4 8a 04 3a 32 45 f3 88 01 8b 43 04 8b 13 2b c2 8b 4d e0 3b c8}  //weight: 30, accuracy: High
        $x_20_2 = {03 d1 8d 41 01 89 45 e0 89 55 e4 33 d2 f7 75 e8 8a 04 3a 8b 55 e4 32 02 c0 c8 04 32 c1 83 7d ec 00 88 45 f3}  //weight: 20, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ValleyRAT_AHD_2147970210_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ValleyRAT.AHD!MTB"
        threat_id = "2147970210"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ValleyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "High"
    strings:
        $x_30_1 = "e5b6ebe2bd1f6b7045bc74f32a72e14bb78b" ascii //weight: 30
        $x_20_2 = "bdbc1e81bf8b79b6dcd496e814853965" ascii //weight: 20
        $x_10_3 = ".com/GT955888/encrypted.bin" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ValleyRAT_AHE_2147972296_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ValleyRAT.AHE!MTB"
        threat_id = "2147972296"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ValleyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "150"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "start login..info" ascii //weight: 50
        $x_40_2 = "LoginManager13SendConditionEb" ascii //weight: 40
        $x_30_3 = "LoginManager13FilterProcessEP" ascii //weight: 30
        $x_20_4 = "LoginManager9GetScreenER" ascii //weight: 20
        $x_10_5 = "K7TSecurity.exe" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ValleyRAT_SLXE_2147973657_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ValleyRAT.SLXE!!MTB"
        threat_id = "2147973657"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ValleyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {ff d0 89 c2 8b 45 f0 0f af c2 89 45 e0 8b 55 f0 8b 45 ec 01 d0 0f b6 00 88 45 e6 0f b6 45 e6 32 45 f7 88 45 e5 8b 55 f0 8b 45 e8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ValleyRAT_PGVE_2147973707_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ValleyRAT.PGVE!MTB"
        threat_id = "2147973707"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ValleyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {45 33 ed 85 ff 74 ?? 49 8b cc 80 31 b7 48 ff c1 49 83 ee 01 75}  //weight: 5, accuracy: Low
        $x_5_2 = {6b 91 f5 5a 2f f0 9b 09 2f f0 9b 09 2f f0 9b 09 64 88 98 08 2a f0 9b 09 64 88 9e 08 a4 f0 9b 09 64 88 9f 08 25 f0 9b 09 7d}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ValleyRAT_AB_2147976870_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ValleyRAT.AB!MTB"
        threat_id = "2147976870"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ValleyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b c1 c1 e0 0d 33 c8 8b c1 c1 e8 11 33 c8 8b c1 c1 e0 05 33 c8 8a 04 3a 32 c1 88 07 47 83 ed}  //weight: 5, accuracy: High
        $x_5_2 = {8b 6c 24 18 50 6a 20 68 b3 09 00 00 56 ff d5 8b 7c 24 1c 85 c0}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

