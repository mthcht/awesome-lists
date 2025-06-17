rule Trojan_Win32_Formbook_2147740231_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook!MTB"
        threat_id = "2147740231"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 3a 8b c8 c1 e9 ?? 33 cf 81 e1 ?? ?? ?? ?? c1 e0 ?? 33 84 8d ?? ?? ?? ?? 42 4e 75 e2}  //weight: 1, accuracy: Low
        $x_1_2 = {b8 67 66 66 66 f7 e9 c1 fa 03 8b c2 c1 e8 1f 03 c2 8d 04 80 03 c0 03 c0 8b d1 2b d0 8a 04 3a 88 8c 0d ?? ?? ?? ?? 88 84 0d ?? ?? ?? ?? 41 81 f9 ?? ?? ?? ?? 7c ca}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Formbook_PA_2147743858_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.PA!MTB"
        threat_id = "2147743858"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 d2 8b c1 f7 f3 8b 45 a0 41 8a 54 15 f4 30 54 01 ff 3b 4c 37 fc 72 e8}  //weight: 10, accuracy: High
        $x_10_2 = {50 6a 00 ff 15 ?? ?? ?? ?? 8b f8 57 6a 00 ff 15 ?? ?? ?? ?? 57 6a 00 8b f0 ff 15 ?? ?? ?? ?? 50 ff 15}  //weight: 10, accuracy: Low
        $x_1_3 = "LoadResource" ascii //weight: 1
        $x_1_4 = "LockResource" ascii //weight: 1
        $x_1_5 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Formbook_AB_2147750880_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.AB!MTB"
        threat_id = "2147750880"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "qhj ZtuQha;jdfn[iaetr" wide //weight: 1
        $x_1_2 = "sBspKBs" ascii //weight: 1
        $x_1_3 = "Gs8LHszJHs" ascii //weight: 1
        $x_1_4 = "CDsaCDs9gDs" ascii //weight: 1
        $x_1_5 = "MSVBVM60.DLL" ascii //weight: 1
        $x_1_6 = "http://members.xoom.com/devsfort/index.html" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Formbook_AB_2147750880_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.AB!MTB"
        threat_id = "2147750880"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 04 17 8a ca 32 c2 2a c8 80 c1 14 c0 c9 02 32 ca 2a ca f6 d1 32 ca 02 ca f6 d1 80 c1 37 32 ca 88 0c 17 42 3b d3 72}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Formbook_AB_2147750880_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.AB!MTB"
        threat_id = "2147750880"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e2 89 55 ?? 8b 45 ?? 03 45 ?? 89 45 ?? 8b 4d ?? 03 4d ?? 89 4d ?? c7 45 ?? ?? ?? ?? ?? 8b 55 ?? 8b 4d ?? d3 ea 89 55 ?? 8b 45 ?? 03 45 ?? 89 45 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8b 4d ?? 33 4d ?? 89 4d ?? 8b 55 ?? 33 55 ?? 89 55 ?? 8b 45 ?? 2b 45 ?? 89 45 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Formbook_AC_2147750920_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.AC!MTB"
        threat_id = "2147750920"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ZELOPHOBIA" wide //weight: 1
        $x_1_2 = "Returportoen5" wide //weight: 1
        $x_1_3 = "filiality" wide //weight: 1
        $x_1_4 = "CDsaCDs9gDs" ascii //weight: 1
        $x_1_5 = "MSVBVM60.DLL" ascii //weight: 1
        $x_1_6 = "suspected" wide //weight: 1
        $x_1_7 = "Squelcher1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Formbook_DSK_2147753182_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.DSK!MTB"
        threat_id = "2147753182"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 55 0c 03 55 ec 8b 45 08 03 45 f8 8a 0a 32 08 8b 55 0c 03 55 ec 88 0a e9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Formbook_PB_2147753877_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.PB!MTB"
        threat_id = "2147753877"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d f8 8b 45 fc 6a 00 81 c1 00 80 c1 2a 68 80 96 98 00 15 21 4e 62 fe 50 51 e8 ?? ?? 00 00 83 fa 07 7c ?? 7f ?? 3d ff 6f 40 93 76 ?? 83 c8 ff 8b d0 8b 4d 08 85 c9 74}  //weight: 1, accuracy: Low
        $x_2_2 = "\\GoldernCrypter\\" ascii //weight: 2
        $x_2_3 = "OPERATION SUCCESSFUL!!" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Formbook_PC_2147754177_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.PC!MTB"
        threat_id = "2147754177"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 78 01 8a 10 40 84 d2 75 ?? 2b c7 8b f8 33 d2 8b c1 f7 f7 41 8a 92 ?? ?? ?? 00 30 54 31 ff 3b cb 72}  //weight: 1, accuracy: Low
        $x_1_2 = "GoldernCrypter" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Formbook_PG_2147754236_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.PG!MTB"
        threat_id = "2147754236"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 28 88 44 24 ?? 8b c1 0f af c6 0f af c7 8b d8 89 44 24 ?? 2b da 0f af d9 0f af df e8 ?? ?? ?? ?? 0b c2 59 74 08 ff 05 ?? ?? ?? 00 eb 06 ff 05 ?? ?? ?? 00 30 5c 24}  //weight: 1, accuracy: Low
        $x_1_2 = {85 ff 0f b6 44 24 ?? 8b f3 0f b6 ca 0f 45 c8 8b 44 24 ?? 0f af c7 88 0c 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Formbook_VC_2147758059_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.VC!MTB"
        threat_id = "2147758059"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 14 06 8b 45 ?? 8a 04 01 30 02 83 f9 ?? 41 30 1a 8b 45 ?? 46 3b f7 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Formbook_VD_2147758280_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.VD!MTB"
        threat_id = "2147758280"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 fc 8a 80 ?? ?? ?? ?? 34 ?? 8b 55 ?? 03 55 ?? 88 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Formbook_MK_2147760054_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.MK!MTB"
        threat_id = "2147760054"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 f4 7a 23 00 00 0f bf 15 ?? ?? ?? ?? 83 f2 ?? 0f bf 05 ?? ?? ?? ?? 3b d0 c7 45 f8 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 81 f1 ?? ?? ?? ?? 39 0d ?? ?? ?? ?? 7f 07}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Formbook_MK_2147760054_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.MK!MTB"
        threat_id = "2147760054"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 0c 83 c4 0c 57 68 80 00 00 00 6a 03 57 6a 01 68 00 00 00 80 ff 70 04 ff 15}  //weight: 10, accuracy: High
        $x_10_2 = {6a 40 68 00 30 00 00 50 57 89 45 f0 ff 15 ?? ?? ?? ?? 57 8b d8 8d 45 d4 50 ff 75 f0 53 56 ff 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Formbook_MK_2147760054_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.MK!MTB"
        threat_id = "2147760054"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RinKerygma" ascii //weight: 1
        $x_1_2 = "DrawIncisure64" ascii //weight: 1
        $x_1_3 = "DisableAxil" ascii //weight: 1
        $x_1_4 = "ToGangway" ascii //weight: 1
        $x_1_5 = "RejectSelenium.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Formbook_MK_2147760054_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.MK!MTB"
        threat_id = "2147760054"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ReceiveKnit64" ascii //weight: 1
        $x_1_2 = "BeginLawn32" ascii //weight: 1
        $x_1_3 = "ReleaseSeraglio" ascii //weight: 1
        $x_1_4 = "LearnGlossa64" ascii //weight: 1
        $x_1_5 = "ReceiveAbettor32" ascii //weight: 1
        $x_1_6 = "BelieveEsthesia64.dll" ascii //weight: 1
        $x_1_7 = "Sunhats" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Formbook_MK_2147760054_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.MK!MTB"
        threat_id = "2147760054"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 cf 10 c1 cb ?? 33 fb 8b da 81 e3 ?? ?? ?? ?? 0f b6 1c 9d ?? ?? ?? ?? 8b 1c 9d ?? ?? ?? ?? c1 ea ?? 0f b6 14 95 02 c1 c3 00 33 fb 33 3c 95 03 89 79 ?? 4e 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {33 cf 81 e2 ?? ?? ?? ?? 33 ca 33 48 ?? 89 48 ?? 8b 50 ?? 33 d1 8b 48 ?? 33 ca 89 50 ?? 8b 50 ?? 33 d1 89 48 ?? 89 50 ?? 83 c6 ?? 83 c0 08 83 fe ?? 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Formbook_MK_2147760054_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.MK!MTB"
        threat_id = "2147760054"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DrawTitmouse" wide //weight: 1
        $x_1_2 = "StartPastel" wide //weight: 1
        $x_1_3 = "Galliwasp" ascii //weight: 1
        $x_1_4 = "FindOligarch64" wide //weight: 1
        $x_1_5 = "LeadBongo32" wide //weight: 1
        $x_1_6 = "_LoseFrithstool.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Formbook_MK_2147760054_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.MK!MTB"
        threat_id = "2147760054"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "UnloadmapNipplewort" ascii //weight: 1
        $x_1_2 = "BringPinup" ascii //weight: 1
        $x_1_3 = "WinEstablishmentarian" ascii //weight: 1
        $x_1_4 = "UnhookFiddleback" ascii //weight: 1
        $x_1_5 = "CarryPlaymate" ascii //weight: 1
        $x_1_6 = "SwitchPyelography32" ascii //weight: 1
        $x_1_7 = "ReleaseYuan32.dll" ascii //weight: 1
        $x_1_8 = "Streptokinase" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Trojan_Win32_Formbook_MA_2147761090_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.MA!MTB"
        threat_id = "2147761090"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {81 c3 de 41 00 00 b9 de 89 00 00 48 40 81 c1 2a b0 00 00 81 e1 51 57 00 00 c2 e3 ba f7 d2 81 f2 34 12 01 00 4a 2d ad 38 00 00 4b 42 5b 81 c2 bc 5b 01 00 3d c9 55 00 00 74 0d}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Formbook_MA_2147761090_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.MA!MTB"
        threat_id = "2147761090"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b c8 85 c9 74 1c 8b c7 2b c8 bb 05 1a 00 00 8b ff 8a 04 0f 88 07 8d 7f 01 4b 75}  //weight: 5, accuracy: High
        $x_5_2 = "WIOSOSOSOW" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Formbook_MA_2147761090_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.MA!MTB"
        threat_id = "2147761090"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CoverWaterage64" ascii //weight: 1
        $x_1_2 = "RememberFlinch32" ascii //weight: 1
        $x_1_3 = "ToElectroencephalography" ascii //weight: 1
        $x_1_4 = "RememberShipwright" ascii //weight: 1
        $x_1_5 = "SpeakCatamountain" ascii //weight: 1
        $x_1_6 = "Newspaperwoman" ascii //weight: 1
        $x_1_7 = "_CutCobble32.dll" ascii //weight: 1
        $x_1_8 = "Sunhats" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Trojan_Win32_Formbook_MB_2147762357_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.MB!MTB"
        threat_id = "2147762357"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "WA_VMSIB" ascii //weight: 3
        $x_3_2 = "fbcreateuser" ascii //weight: 3
        $x_3_3 = "T__23e31c0U" ascii //weight: 3
        $x_3_4 = "base64Binary" ascii //weight: 3
        $x_3_5 = "SysDateTimePick32" ascii //weight: 3
        $x_3_6 = "GetMonitorInfoA" ascii //weight: 3
        $x_3_7 = {61 35 62 4b 62 61 62 77 62 8d 62 a6 62 bc 62 d2 62 e8 62 fe 62 14 62 2a 63 49 63 5b 63 71 63 87 63 9d 63}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Formbook_MB_2147762357_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.MB!MTB"
        threat_id = "2147762357"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Busybody" ascii //weight: 1
        $x_1_2 = "ChangeMadreporite" ascii //weight: 1
        $x_1_3 = "ToCartulary" ascii //weight: 1
        $x_1_4 = "FeelDiosgenin32" ascii //weight: 1
        $x_1_5 = "UnlockBaddeleyite64" ascii //weight: 1
        $x_1_6 = "ShowSprechgesang" ascii //weight: 1
        $x_1_7 = "_PayTelegony" ascii //weight: 1
        $x_1_8 = "ChooseMontage32.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Formbook_MB_2147762357_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.MB!MTB"
        threat_id = "2147762357"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 14 8b 4d 10 8b 55 0c 8b 75 08 31 ff c7 45 f0 00 00 00 00 8b 5d 10 89 1c 24 c7 44 24 04 00 00 00 80 c7 44 24 08 07 00 00 00 c7 44 24 0c 00 00 00 00 c7 44 24 10 03 00 00 00 c7 44 24 14 80 00 00 00 c7 44 24 18 00 00 00 00 89 45 d8 89 4d d4 89 55 d0 89 75 cc 89 7d c8 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {83 ec 08 31 c9 89 45 e0 8b 45 e0 c7 04 24 00 00 00 00 89 44 24 04 c7 44 24 08 00 30 00 00 c7 44 24 0c 40 00 00 00 89 4d c0 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {88 14 08 8b 45 e4 8b 4d dc 0f b6 34 08 89 f2 [0-7] 88 14 08 8b 45 dc 83 c0 01 89 45 dc e9 ?? fe ff ff}  //weight: 1, accuracy: Low
        $x_1_4 = "SHEmptyRecycleBinW" ascii //weight: 1
        $x_1_5 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_6 = "Sleep" ascii //weight: 1
        $x_1_7 = "CreateThreadpoolTimer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Formbook_FB_2147762930_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.FB!MTB"
        threat_id = "2147762930"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 51 a1 ?? ?? ?? ?? 8b 08 8b 15 ?? ?? ?? ?? 8b 04 91 2d ?? ?? ?? 00 89 45 fc 8b 0d ?? ?? ?? ?? 83 c1 01 89 0d ?? ?? ?? ?? 8b 45 fc 8b e5 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Formbook_AK_2147766119_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.AK!MTB"
        threat_id = "2147766119"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {81 f2 1f 96 00 00 43 2d 10 03 00 00 81 f1 b2 b1 00 00 b9 92 1b 00 00 5a 81 e2 d7 78 01 00 05 76 8e 00 00 f7 d3 4a 81 e1 40 9c 00 00 05 76 d6 00 00 81 fa 1f 96 00 00 74 14}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Formbook_AK_2147766119_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.AK!MTB"
        threat_id = "2147766119"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FILEINSTALL ( \"biopsies\" , @TEMPDIR & \"\\biopsies\" , 1 )" ascii //weight: 1
        $x_1_2 = "81 116 119 112 90 123 112 121" ascii //weight: 1
        $x_1_3 = "FILEWRITE ( 818 , \"07ekpXoM\" )" ascii //weight: 1
        $x_1_4 = "HOTKEYSET ( \"eFnO2BEwhd" ascii //weight: 1
        $x_1_5 = "CONSOLEWRITE ( \"16lsG6Dw\" )" ascii //weight: 1
        $x_1_6 = "REGDELETE ( \"default\" , \"R8pbb7J2\" )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Formbook_SB_2147781179_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.SB!MTB"
        threat_id = "2147781179"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Users\\Pc\\Desktop\\Posleden stub\\A_great_ut177987882004\\quickTray.vbp" wide //weight: 1
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run-" wide //weight: 1
        $x_1_3 = "\\Folders.lst" wide //weight: 1
        $x_1_4 = "ShellExecuteA" ascii //weight: 1
        $x_1_5 = "http://rbgCODE.com" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Formbook_AT_2147789559_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.AT!MTB"
        threat_id = "2147789559"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {56 8b 75 08 2b f0 8a 10 49 88 14 06 40 85 c9 7f f5}  //weight: 10, accuracy: High
        $x_10_2 = {8b 4d fc 8a 04 39 03 cf 88 45 f4 8d 50 c0 80 fa 1f 77 18}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Formbook_RPS_2147811598_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.RPS!MTB"
        threat_id = "2147811598"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 ff 4d 98 90 90 90 90}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Formbook_SIBA_2147812659_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.SIBA!MTB"
        threat_id = "2147812659"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 11 83 f2 ?? 8b 45 ?? 03 45 ?? 88 10}  //weight: 1, accuracy: Low
        $x_1_2 = {88 10 8b 4d ?? 03 4d ?? 0f b6 11 83 c2 ?? 8b 45 00 03 45 01 88 10}  //weight: 1, accuracy: Low
        $x_1_3 = {88 10 8b 4d ?? 03 4d ?? 8a 11 80 ea ?? 8b 45 00 03 45 01 88 10}  //weight: 1, accuracy: Low
        $x_1_4 = {83 c2 01 89 55 ?? 8b 45 00 3b 45 ?? 6a 00 8b 4d ?? 51 6a 00 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Formbook_RPB_2147814004_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.RPB!MTB"
        threat_id = "2147814004"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 04 39 2c 59 34 4e 2c 6c 34 8d fe c0 34 d6 2c 1c 88 04 39 41 3b cb 72 e7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Formbook_RPC_2147814005_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.RPC!MTB"
        threat_id = "2147814005"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 04 39 2c 2a 34 4c 04 12 34 05 2c 5e 34 f3 04 0c 88 04 39 41 3b cb 72 e7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Formbook_RPE_2147814102_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.RPE!MTB"
        threat_id = "2147814102"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 99 6a 0c 5e f7 fe 8a 82 ?? ?? ?? ?? 30 04 19 41 3b cf 72 ea}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Formbook_RPE_2147814102_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.RPE!MTB"
        threat_id = "2147814102"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 19 04 ?? 34 ?? 04 ?? 88 04 19 41 3b cf 72 ef}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Formbook_RPF_2147814103_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.RPF!MTB"
        threat_id = "2147814103"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 39 04 ?? 34 ?? 04 ?? 88 04 39 41 3b cb 72 ef}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Formbook_RPG_2147814104_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.RPG!MTB"
        threat_id = "2147814104"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 19 2c ?? 34 ?? 2c ?? 34 ?? 2c ?? 34 ?? 88 04 19 41 3b cf 72 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Formbook_ME_2147814547_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.ME!MTB"
        threat_id = "2147814547"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 0c 8b 0c 10 51 ff 15 2d 00 a3 ?? ?? ?? ?? 6a 00 68 80 00 00 00 6a 03 6a 00 6a 07 68 00 00 00 80 ba 04 00 00 00 c1 e2}  //weight: 1, accuracy: Low
        $x_1_2 = "IsProcessorFeaturePresent" ascii //weight: 1
        $x_1_3 = "OutputDebugStringW" ascii //weight: 1
        $x_1_4 = "InternetLockRequestFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Formbook_RPT_2147816492_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.RPT!MTB"
        threat_id = "2147816492"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 0f ef c5 66 0f fc c6 66 0f ef c7 66 0f fc c2 66 0f ef c3 f3 0f 7f 01 83 c1 20 83 c2 e0 0f 85}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Formbook_MG_2147817131_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.MG!MTB"
        threat_id = "2147817131"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "Hkcoedclxfkckdl" ascii //weight: 10
        $x_2_2 = {83 c1 01 89 [0-6] 8b [0-6] 3b [0-6] 0f 83 [0-5] 8b 45 ?? 03 [0-6] 8a 08 88 [0-6] 0f b6 [0-64] f7 d2 88 [0-6] 0f b6}  //weight: 2, accuracy: Low
        $x_2_3 = "SetClipboardData" ascii //weight: 2
        $x_2_4 = "Sleep" ascii //weight: 2
        $x_2_5 = "GetTempPathA" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Formbook_MH_2147817605_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.MH!MTB"
        threat_id = "2147817605"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 45 cc 6a 00 68 80 00 00 00 6a 03 6a 00 6a 01 68 00 00 00 80 ba 04 00 00 00 c1 e2 00 8b 45 cc 8b 0c 10 51 ff}  //weight: 1, accuracy: High
        $x_1_2 = {0f b6 11 83 c2 3a 8b 45 f8 03 45 fc 88 10 8b 4d f8 03 4d fc 0f b6 11 81 f2 86 00 00 00 8b 45 f8 03 45 fc 88 10 8b 4d f8 03 4d fc 8a 11 80 ea 01 8b 45 f8 03 45 fc 88 10 8b 4d f8 03 4d fc 8a 11 80 c2 01 8b 45 f8 03 45 fc 88 10 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Formbook_RPR_2147817748_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.RPR!MTB"
        threat_id = "2147817748"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {54 50 46 30 0d 54 5f 5f 31 37 33 30 34 31 35 32 39 36 0d 54 5f 5f 31 37 33 30 33 38 37 30 37 39 04 4c 65 66 74 02 00 03 54 6f 70 02 00 0b 42 6f 72 64 65 72 53 74 79 6c 65 07 08 62 73 44 69 61}  //weight: 1, accuracy: High
        $x_1_2 = {54 50 46 30 06 54 46 6f 72 6d 31 05 46 6f 72 6d 31 04 4c 65 66 74 03 f4 00 03 54 6f 70 02 7c 07 43 61 70 74 69 6f 6e 06 0a 41 73 79 6e 63 20 44 65 6d 6f 0c 43 6c 69 65 6e 74 48 65 69 67 68 74 03 59 02 0b 43 6c 69 65 6e 74 57 69 64 74 68 03 9e 03 05 43 6f 6c 6f 72 07 09 63 6c 42 74 6e 46}  //weight: 1, accuracy: High
        $x_1_3 = {54 50 46 30 06 54 46 6f 72 6d 38 05 46 6f 72 6d 38 04 4c 65 66 74 03 ce 00 03 54 6f 70 03 a3 00 0b 42 6f 72 64 65 72 53 74 79 6c 65 07 08 62 73 44 69 61 6c 6f 67 0c 43 6c 69 65 6e 74 48 65 69}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Formbook_RPR_2147817748_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.RPR!MTB"
        threat_id = "2147817748"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 10 8a 04 37 (04|(34|2c)) ?? (04|(34|2c)) ?? (04|(34|2c)) ?? (04|(34|2c)) ?? (04|(34|2c)) [0-32] 88 04 37 46 3b f3 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Formbook_RPU_2147817974_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.RPU!MTB"
        threat_id = "2147817974"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 39 04 ?? 34 ?? 2c ?? 34 ?? fe c8 88 04 39 41 3b cb 72 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Formbook_RPU_2147817974_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.RPU!MTB"
        threat_id = "2147817974"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b8 f3 bd 00 00 81 fa ef 44 00 00 74 0c bb 76 d6 00 00 40 49 35 fe d7 00 00 c2 a8 07 81 c2 1b 1d 00 00 c2 19 f5 5a 81 c1 45 85 00 00 c2 98 4c c2 18 85 25 f9 5e 00 00 f7 d1 49}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Formbook_SIBB_2147818187_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.SIBB!MTB"
        threat_id = "2147818187"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 c0 80 04 06 ?? [0-80] 8b 4d ?? 80 04 01 ?? [0-80] 8b 4d 02 fe 04 01 [0-80] 8b 4d 02 80 34 01 ?? [0-80] 8b 4d 02 fe 0c 01 [0-80] 39 c3 74 ?? 8b 75 02 40 eb ?? 8b 45 02 ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Formbook_SIBB1_2147818188_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.SIBB1!MTB"
        threat_id = "2147818188"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 c0 80 34 06 ?? [0-80] 8b 4d ?? 80 34 01 ?? [0-80] 8b 4d 02 80 04 01 ?? [0-80] 8b 4d 02 fe 0c 01 [0-80] 8b 4d 02 fe 04 01 [0-80] 39 c3 74 ?? 8b 75 02 40 eb ?? 8b 45 02 ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Formbook_MI_2147824002_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.MI!MTB"
        threat_id = "2147824002"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 74 74 70 3a 2f 2f 61 6c 6d 6f 6e 64 74 72 61 64 69 6e 67 6c 74 64 2e 63 6f 6d 2f [0-5] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_2 = "FEARME" ascii //weight: 1
        $x_1_3 = "LoVEMe" ascii //weight: 1
        $x_1_4 = "LockResource" ascii //weight: 1
        $x_1_5 = "IsProcessorFeaturePresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Formbook_MJ_2147835944_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.MJ!MTB"
        threat_id = "2147835944"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {83 c4 0c 6a 00 68 80 00 00 00 6a 03 6a 00 6a 01 68 00 00 00 80 b9 04 00 00 00 c1 e1 00 8b 55 0c 8b 04 0a 50 ff 15}  //weight: 10, accuracy: High
        $x_10_2 = {89 45 f8 6a 00 8d 85 30 ff ff ff 50 8b 4d a4 51 8b 55 f8 52 8b 45 9c 50 ff 15}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Formbook_ML_2147837036_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.ML!MTB"
        threat_id = "2147837036"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {6a 00 68 80 00 00 00 6a 03 6a 00 6a 01 68 00 00 00 80 b9 04 00 00 00 c1 e1 00 8b 55 0c 8b 04 0a 50 ff 15}  //weight: 10, accuracy: High
        $x_10_2 = {89 45 f8 6a 00 8d 45 e4 50 8b 4d f0 51 8b 55 f8 52 8b 45 ec 50 ff 15}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Formbook_NYW_2147837886_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.NYW!MTB"
        threat_id = "2147837886"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 04 37 04 04 34 dc 04 23 34 cd 04 5d 34 86 2c 17 34 e1 2c 6f 88 04 37 46 3b f3 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Formbook_MBAR_2147839100_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.MBAR!MTB"
        threat_id = "2147839100"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4d f0 3b 4d e0 73 27 8b 45 f0 99 b9 0c 00 00 00 f7 f9 8b 45 e4 0f b6 0c 10 8b 55 dc 03 55 f0 0f b6 02 33 c1 8b 4d dc 03 4d f0 88 01}  //weight: 1, accuracy: High
        $x_1_2 = {83 c4 0c 6a 40 68 00 30 00 00 8b 55 e0 52 6a 00 ff 15 88 60 41 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Formbook_MBAS_2147839700_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.MBAS!MTB"
        threat_id = "2147839700"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 e6 8b c6 c1 ea 03 8d 0c 52 c1 e1 02 2b c1 8a 80 ?? ?? ?? ?? 30 04 1e 46 3b f7 72 de}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Formbook_MBAS_2147839700_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.MBAS!MTB"
        threat_id = "2147839700"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 ab aa aa aa f7 e6 c1 ea 03 8b c6 8d 0c 52 c1 e1 02 2b c1 46 8a 80 ?? ?? ?? ?? 30 44 33 ff 3b f7 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Formbook_RG_2147840213_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.RG!MTB"
        threat_id = "2147840213"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 0e 0f b6 c0 8d 95 ?? ?? ff ff 03 d0 47 0f b6 02 88 06 0f b6 c1 88 0a 02 06 8b 4d ?? 0f b6 c0 0f b6 84 05 ?? ?? ff ff 32 c3 88 44 0f ?? 3b 7d ?? 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Formbook_RE_2147841479_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.RE!MTB"
        threat_id = "2147841479"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 f0 f7 e1 d1 ea 83 e2 fc 8d 04 52 f7 d8 8a 84 06 ?? ?? ?? ?? 30 04 33 46 39 f7 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Formbook_RE_2147841479_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.RE!MTB"
        threat_id = "2147841479"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {52 4f 38 00 20 32 0d 0a 00 00 00 00 ff cc 31 00 00 5a 38 a8 dd 00 61 ce 40 8d 46 3d}  //weight: 5, accuracy: High
        $x_1_2 = "Industrialenono.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Formbook_RPW_2147842409_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.RPW!MTB"
        threat_id = "2147842409"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 b8 89 45 a8 8b 45 cc b9 0c 00 00 00 99 f7 f9 8b 45 a8 0f b6 34 10 8b 45 d0 8b 4d cc 0f b6 14 08 31 f2 88 14 08 8b 45 cc 83 c0 01 89 45 cc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Formbook_RPZ_2147846186_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.RPZ!MTB"
        threat_id = "2147846186"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b8 ab aa aa 2a f7 eb c1 fa 02 8b da c1 eb 1f 03 da 75 ed}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Formbook_RPZ_2147846186_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.RPZ!MTB"
        threat_id = "2147846186"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 55 fc 83 c2 01 89 55 fc 81 7d fc 7f 17 00 00 7d 27 8b 45 fc 99 b9 0c 00 00 00 f7 f9 8b 45 ec 0f b6 0c 10 8b 55 f8 03 55 fc 0f b6 02 33 c1 8b 4d f8 03 4d fc 88 01 eb c7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Formbook_RPZ_2147846186_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.RPZ!MTB"
        threat_id = "2147846186"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Rimeless.Hob" wide //weight: 1
        $x_1_2 = "Blomkaalshovedets.ana" wide //weight: 1
        $x_1_3 = "skuffekomediers" wide //weight: 1
        $x_1_4 = "Fringebaad" wide //weight: 1
        $x_1_5 = "husassistent.xav" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Formbook_ARAA_2147846651_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.ARAA!MTB"
        threat_id = "2147846651"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8a 04 37 2c 02 34 69 04 0a 34 0c 2c 34 88 04 37 46 3b f3 72 eb}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Formbook_RPX_2147850139_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.RPX!MTB"
        threat_id = "2147850139"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 11 88 55 fe 0f b6 45 ff c1 f8 03 0f b6 4d ff c1 e1 05 0b c1 0f b6 55 fe 33 c2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Formbook_RPX_2147850139_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.RPX!MTB"
        threat_id = "2147850139"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 00 88 45 fe 0f b6 45 ff c1 f8 03 0f b6 4d ff c1 e1 05 0b c1 0f b6 4d fe 33 c1 8b 4d f8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Formbook_RPX_2147850139_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.RPX!MTB"
        threat_id = "2147850139"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 55 ff 8b 45 d8 03 45 f0 8a 08 88 4d fe 0f b6 55 ff c1 fa 03 0f b6 45 ff c1 e0 05 0b d0 0f b6 4d fe 33 d1 8b 45 f8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Formbook_RPX_2147850139_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.RPX!MTB"
        threat_id = "2147850139"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 11 88 55 fe 0f b6 45 ff c1 f8 03 0f b6 4d ff c1 e1 05 0b c1 0f b6 55 fe 33 c2 8b 4d f0 03 4d f4 88 01 8b 45 e8 83 c0 01 99}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Formbook_RPY_2147850140_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.RPY!MTB"
        threat_id = "2147850140"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 45 ff 0f b6 45 ff 83 f0 53 88 45 ff 0f b6 45 ff 2b 45 f8 88 45 ff 0f b6 45 ff c1 f8 03 0f b6 4d ff c1 e1 05 0b c1 88 45 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Formbook_RPY_2147850140_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.RPY!MTB"
        threat_id = "2147850140"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2b 45 f8 88 45 ff 0f b6 45 ff c1 f8 03 0f b6 4d ff c1 e1 05 0b c1 88 45 ff 0f b6 45 ff 83 f0 1f 88 45 ff 8b 45 f0 03 45 f8 8a 4d ff 88 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Formbook_BL_2147897283_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.BL!MTB"
        threat_id = "2147897283"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 55 ff c1 fa 03 0f b6 45 ff c1 e0 05 0b d0 0f b6 4d fe 33 d1 8b 45 f8 88 90 c0 75 42 00}  //weight: 1, accuracy: High
        $x_1_2 = "htdocs\\dac248d5227e478b996e2ce239c562d9" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Formbook_AMAT_2147916813_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.AMAT!MTB"
        threat_id = "2147916813"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-30] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-30] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 2, accuracy: Low
        $x_1_3 = {45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 44 00 6c 00 6c 00 43 00 22 00 20 00 26 00 20 00 22 00 61 00 6c 00 6c 00 28 00 [0-15] 28 00 22 00}  //weight: 1, accuracy: Low
        $x_1_4 = {45 58 45 43 55 54 45 20 28 20 22 44 6c 6c 43 22 20 26 20 22 61 6c 6c 28 [0-15] 28 22}  //weight: 1, accuracy: Low
        $x_1_5 = "EXECUTE ( \"S\" & \"trin\" & \"gM\" & \"id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Formbook_AMA_2147921786_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.AMA!MTB"
        threat_id = "2147921786"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-47] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 2, accuracy: Low
        $x_1_3 = {45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 44 00 6c 00 6c 00 43 00 61 00 6c 00 6c 00 28 00 [0-20] 28 00 22 00 22 00 [0-20] 22 00 22 00 2c 00 20 00 22 00 22 00 54 00 63 00 35 00 35 00 73 00 32 00 57 00 71 00 4d 00 22 00 22 00 29 00 2c 00 20 00 00 28 00 22 00 22 00 [0-20] 22 00 22 00 2c 00 20 00 22 00 22 00 54 00 63 00 35 00 35 00 73 00 32 00 57 00 71 00 4d 00 22 00 22 00 29 00}  //weight: 1, accuracy: Low
        $x_1_4 = {45 58 45 43 55 54 45 20 28 20 22 44 6c 6c 43 61 6c 6c 28 [0-20] 28 22 22 [0-20] 22 22 2c 20 22 22 54 63 35 35 73 32 57 71 4d 22 22 29 2c 20 00 28 22 22 [0-20] 22 22 2c 20 22 22 54 63 35 35 73 32 57 71 4d 22 22 29}  //weight: 1, accuracy: Low
        $x_1_5 = {4c 00 4f 00 43 00 41 00 4c 00 20 00 24 00 [0-30] 20 00 3d 00 20 00 4d 00 4f 00 44 00 20 00 28 00 20 00 [0-30] 20 00 28 00 20 00 24 00 [0-30] 20 00 29 00 20 00 2d 00 20 00 01 20 00 28 00 20 00 53 00 54 00 52 00 49 00 4e 00 47 00 4d 00 49 00 44 00 20 00 28 00 20 00 24 00 [0-30] 20 00 2c 00 20 00 4d 00 4f 00 44 00 20 00 28 00 20 00 24 00 [0-30] 20 00 2b 00 20 00 2d 00 31 00 20 00 2c 00 20 00 24 00 [0-30] 20 00 29 00 20 00 2b 00 20 00 31 00 20 00 2c 00 20 00 31 00 20 00 29 00 20 00 29 00 20 00 2c 00 20 00 32 00 35 00 36 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_6 = {4c 4f 43 41 4c 20 24 [0-30] 20 3d 20 4d 4f 44 20 28 20 [0-30] 20 28 20 24 [0-30] 20 29 20 2d 20 01 20 28 20 53 54 52 49 4e 47 4d 49 44 20 28 20 24 [0-30] 20 2c 20 4d 4f 44 20 28 20 24 [0-30] 20 2b 20 2d 31 20 2c 20 24 [0-30] 20 29 20 2b 20 31 20 2c 20 31 20 29 20 29 20 2c 20 32 35 36 20 29}  //weight: 1, accuracy: Low
        $x_1_7 = {26 00 3d 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 41 00 73 00 63 00 28 00 53 00 74 00 72 00 69 00 6e 00 67 00 4d 00 69 00 64 00 28 00 24 00 [0-20] 2c 00 20 00 24 00 [0-20] 2c 00 20 00 31 00 29 00 29 00 20 00 26 00 20 00 22 00 22 00 20 00 22 00 22 00 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_8 = {26 3d 20 45 58 45 43 55 54 45 20 28 20 22 41 73 63 28 53 74 72 69 6e 67 4d 69 64 28 24 [0-20] 2c 20 24 [0-20] 2c 20 31 29 29 20 26 20 22 22 20 22 22 22 20 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Formbook_ILM_2147937609_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Formbook.ILM!MTB"
        threat_id = "2147937609"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Formbook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 4c 30 01 80 e9 ?? 30 0c 30 40 3b c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

