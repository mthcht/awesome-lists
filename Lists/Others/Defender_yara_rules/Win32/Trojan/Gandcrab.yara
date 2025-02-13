rule Trojan_Win32_Gandcrab_AF_2147727324_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gandcrab.AF"
        threat_id = "2147727324"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gandcrab"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {eb 03 c2 0c 00 55 8b ec 81 ec 00 10 00 00 c7 45 ?? ?? ?? 00 00 c7 45 ?? 00 00 40 00}  //weight: 10, accuracy: Low
        $x_10_2 = {e8 04 00 00 00 00 00 00 00 58 89 [0-5] 8b 00 85 c0 74 03 c9 ff e0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gandcrab_S_2147730771_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gandcrab.S!MTB"
        threat_id = "2147730771"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gandcrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "'dll::NtC',t 'reat', t 'eSect',t'ion(p  r2,i ', i  0xE,t ',n,')" ascii //weight: 1
        $x_1_2 = "ntdll::NtMapViewOfSection(p" ascii //weight: 1
        $x_1_3 = "kernel32::CloseHandle(i" ascii //weight: 1
        $x_1_4 = "kernel32::CreateFile(p" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gandcrab_AD_2147740935_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gandcrab.AD!MTB"
        threat_id = "2147740935"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gandcrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 44 19 01 0f b6 14 19 88 54 24 ?? 88 44 24 ?? 8a 44 19 ?? 8a d0 c0 e2 ?? 0a 54 19 ?? 8d 74 24 ?? 8d 7c 24 ?? 88 54 24 ?? e8}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 4c 24 ?? 8b 44 24 ?? 0f b6 54 24 ?? 88 0c 28 0f b6 4c 24 ?? 45 88 14 28 8b 54 24 ?? 45 88 0c 28 83 c3 04 45 3b 1a 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Gandcrab_GM_2147743722_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gandcrab.GM!MTB"
        threat_id = "2147743722"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gandcrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c7 c1 e8 05 03 45 ?? 8b cf c1 e1 04 03 4d ?? 33 c1 8b 4d ?? 81 45 fc ?? ?? ?? ?? 03 cf 33 c1 2b d8 ff 4d ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gandcrab_GM_2147743722_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gandcrab.GM!MTB"
        threat_id = "2147743722"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gandcrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f be 18 e8 ?? ?? ?? ?? 33 d8 8b 4d ?? 03 4d ?? 88 19 eb 14 00 8d 55 ?? 52 6a ?? 6a ?? ff 15 ?? ?? ?? ?? 8b 45 ?? 03 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gandcrab_RG_2147745279_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gandcrab.RG!MTB"
        threat_id = "2147745279"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gandcrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {a1 6c a2 40 00 03 85 ?? ?? ?? ?? 8b 0d b4 aa 40 00 03 8d ?? ?? ?? ?? 8a 89 a0 ec 0b 00 88 08 81 bd ?? ?? ?? ?? 22 06 00 00 7d}  //weight: 1, accuracy: Low
        $x_1_2 = {03 45 e4 8b 4d d4 03 4d ec 33 c1 8b 4d d4 c1 e9 05 03 4d e8 33 c1 8b 4d f0 2b c8 89 4d f0 81 7d fc 49 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gandcrab_PVD_2147747895_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gandcrab.PVD!MTB"
        threat_id = "2147747895"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gandcrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 6c 24 10 02 c0 02 c0 0a 04 29 c0 e3 06 0a 5c 29 02 88 04 3e 88 54 3e 01 88 5c 3e 02 83 c1 04 83 c6 03 3b 4c 24 14 72}  //weight: 2, accuracy: High
        $x_2_2 = {8b 45 f8 2b fe 8b 4d dc 05 47 86 c8 61 83 6d f0 01 89 7d f4 89 45 f8 0f 85}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Gandcrab_RB_2147748468_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gandcrab.RB!MSR"
        threat_id = "2147748468"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gandcrab"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $n_50_1 = "360NetBase.dll" wide //weight: -50
        $n_50_2 = "360Decryptor_PrivateKey.ini" wide //weight: -50
        $n_50_3 = "360.cn Inc" wide //weight: -50
        $n_50_4 = "TeslaCryptDecoder.dll" wide //weight: -50
        $n_50_5 = "Release\\TeslaCryptDecoder.pdb" ascii //weight: -50
        $x_20_6 = "GDCB-DECRYPT.txt" wide //weight: 20
        $x_20_7 = "nomoreransom" ascii //weight: 20
        $x_1_8 = "AVP.EXE" wide //weight: 1
        $x_1_9 = "ekrn.exe" wide //weight: 1
        $x_1_10 = "avgnt.exe" wide //weight: 1
        $x_1_11 = "ashDisp.exe" wide //weight: 1
        $x_1_12 = "NortonAntiBot.exe" wide //weight: 1
        $x_1_13 = "Mcshield.exe" wide //weight: 1
        $x_1_14 = "avengine.exe" wide //weight: 1
        $x_1_15 = "cmdagent.exe" wide //weight: 1
        $x_1_16 = "smc.exe" wide //weight: 1
        $x_1_17 = "persfw.exe" wide //weight: 1
        $x_1_18 = "pccpfw.exe" wide //weight: 1
        $x_1_19 = "fsguiexe.exe" wide //weight: 1
        $x_1_20 = "cfp.exe" wide //weight: 1
        $x_1_21 = "msmpeng.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_20_*) and 5 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Gandcrab_RL_2147748498_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gandcrab.RL!MTB"
        threat_id = "2147748498"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gandcrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 ff 15 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8b cf 8b c7 c1 e9 ?? 03 4c 24 ?? c1 e0 ?? 03 44 24 ?? 33 c8 8d 04 2f 33 c8 2b d9 8b cb 8b c3 c1 e9 ?? 03 4c 24 ?? c1 e0 ?? 03 44 24 ?? 33 c8 8d 04 2b 2b 6c 24 ?? 33 c8 2b f9 83 ee ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {69 c9 fd 43 03 00 6a 00 81 c1 c3 9e 26 00 6a 00 89 0d ?? ?? ?? ?? ff d3 8a 15 ?? ?? ?? ?? 30 14 3e 46 3b 75 0c 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Gandcrab_VRD_2147748617_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gandcrab.VRD!MTB"
        threat_id = "2147748617"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gandcrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a c1 8a d9 24 ?? 80 e1 ?? c0 e0 ?? 0a 44 2e ?? 8b 6c 24 ?? 02 c9 02 c9 0a 0c 2e c0 e3 ?? 0a 5c 2e ?? 88 0c 3a 42 88 04 3a 42 88 1c 3a 83 c6 ?? 42 3b 74 24 ?? 72}  //weight: 1, accuracy: Low
        $x_1_2 = {0f be 1c 3e 81 c3 01 10 00 00 e8 ?? ?? ?? ?? fe cb 32 c3 88 04 3e 46 3b f5 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gandcrab_RPD_2147748747_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gandcrab.RPD!MTB"
        threat_id = "2147748747"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gandcrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "cipiwetewavasa %s" ascii //weight: 1
        $x_1_2 = "logejuxosidijoharuxayogora yocicenehozogolehejosazobi lonoziwovazefabofavisefu notudo vozawesojimetasujinefegecipanolu yifozoberi fezidawa zugeniyokuluyesepuhezimosafo" ascii //weight: 1
        $x_2_3 = {30 04 1f 56 ff 15 ?? ?? ?? ?? 56 ff 15 ?? ?? ?? ?? 33 c0 89 b5 e8 f7 ff ff 8d bd ec f7 ff ff ab 8d 85 e8 f7 ff ff 50 56 56 56 ff 15 ?? ?? ?? ?? 8d 85 f4 f7 ff ff 50 56 ff 15 ?? ?? ?? ?? 43 3b 5d}  //weight: 2, accuracy: Low
        $x_2_4 = {8a e3 8a c3 80 e3 f0 c0 e0 06 0a 44 3a ?? 80 e4 fc c0 e3 02 0a 1c 3a c0 e4 04 0a 64 3a ?? 83 c7 04 88 1c 31 88 64 31 01 88 44 31 02 83 c1 03 3b 7d 00 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Gandcrab_CS_2147749689_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gandcrab.CS!eml"
        threat_id = "2147749689"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gandcrab"
        severity = "Critical"
        info = "eml: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 00 6a 00 ff 15 [0-2] 60 40 00 a1 ?? f8 40 00 03 85 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 8d ?? ?? ?? ?? 8a 89 3d 34 03 00 88 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gandcrab_JRL_2147749796_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gandcrab.JRL!MTB"
        threat_id = "2147749796"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gandcrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 04 1e 46 3b f7 7c 12 00 e8 ?? ?? ?? 00}  //weight: 1, accuracy: Low
        $x_1_2 = {00 33 c5 89 45 ?? 69 05 ?? ?? ?? 00 ?? ?? ?? ?? 05 ?? ?? ?? ?? a3 28 00 a1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gandcrab_SGC_2147749797_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gandcrab.SGC!MTB"
        threat_id = "2147749797"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gandcrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b cf c1 e1 ?? 03 8d ?? ?? ?? ?? 33 c1 8b 8d ?? 02 03 cf 33 c1 2b d8 35 00 c1 e8 ?? 03 85 ?? 02}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c3 c1 e8 ?? 03 85 ?? ?? ?? ?? 8b cb c1 e1 ?? 03 8d ?? 02 33 c1 8b 8d ?? 02 03 cb 33 c1 2b f8 42 00 8b bd ?? 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gandcrab_VZD_2147749829_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gandcrab.VZD!MTB"
        threat_id = "2147749829"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gandcrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "wumajamepozotera" ascii //weight: 1
        $x_1_2 = {c0 e1 04 0a 4f ?? c0 e2 06 0a 57 ?? 88 04 1e 46 88 0c 1e 8b 4c 24 ?? 46 88 14 1e 83 c5 04 46 3b 29 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gandcrab_CQS_2147751365_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gandcrab.CQS!MTB"
        threat_id = "2147751365"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gandcrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 44 3a 02 80 e4 fc c0 e3 ?? 0a 1c 3a c0 e4 ?? 0a 64 3a 01 83 c7 ?? 88 1c 31 88 64 31 01 88 44 31 02 83 c1 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gandcrab_DHA_2147751928_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gandcrab.DHA!MTB"
        threat_id = "2147751928"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gandcrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? 8b 45 f4 03 45 fc 0f be 18 e8 ?? ?? ?? ?? 33 d8 8b 4d f4 03 4d fc 88 19 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec a1 ?? ?? ?? ?? 69 c0 ?? ?? ?? ?? 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? c1 e8 10 25 ff 7f 00 00 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gandcrab_RLQ_2147753550_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gandcrab.RLQ!MTB"
        threat_id = "2147753550"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gandcrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e8 49 ff ff ff 30 04 3e 46 3b f3 7c e1}  //weight: 1, accuracy: High
        $x_1_2 = {33 c4 89 84 24 00 04 00 00 a1 78 11 41 00 69 c0 fd 43 03 00 8d 0c 24 51 05 c3 9e 26 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Gandcrab_CC_2147812205_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gandcrab.CC!MTB"
        threat_id = "2147812205"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gandcrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c1 8b 4d dc c1 e9 05 03 4d ec 33 c1 8b 4d f4 2b c8 89 4d}  //weight: 1, accuracy: High
        $x_1_2 = "VirtualProtect" ascii //weight: 1
        $x_1_3 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_4 = "GetTickCount" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gandcrab_RPI_2147821517_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gandcrab.RPI!MTB"
        threat_id = "2147821517"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gandcrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 03 89 75 cc c1 e3 0c 81 6d cc ?? ?? ?? ?? c1 e3 00 81 45 cc ?? ?? ?? ?? c1 e8 07 81 6d cc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

