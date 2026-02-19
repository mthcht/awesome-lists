rule Trojan_Win64_SalatStealer_PSC_2147956566_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SalatStealer.PSC!MTB"
        threat_id = "2147956566"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SalatStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {41 47 67 41 64 41 42 30 41 48 41 41 63 77 41 36 41 43 38 41 4c 77 42 6e 41 47 6b 41 64 41 42 6f 41 48 55 41 59 67 41 75 41 47 4d 41 62 77 42 74 41 43 38 41 63 77 42 68 41 47 30 41 62 67 42 70 41 47 34 41 61 67 42 68 41 44 59 41 4e 67 41 32 41 43 38 [0-31] 41 48 49 41 59 51 42 33 41 43 38 41 63 67 42 6c 41 47 59 41 63 77 41 76 41 47 67 41 5a 51 42 68 41 47 51 41 63 77 41 76 41 47 30 41 59 51 42 70 41 47 34 41 4c 77}  //weight: 5, accuracy: Low
        $x_5_2 = "powershell -ExecutionPolicy Bypass -EncodedCommand %s" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_SalatStealer_FG_2147959571_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SalatStealer.FG!MTB"
        threat_id = "2147959571"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SalatStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 35 78 60 ee 00 0f b6 14 16 31 ea 8b 6c 24 50 88 14 2b 8d 45 01 8d 15 78 48 ed 00 39 42 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_SalatStealer_ABS_2147960464_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SalatStealer.ABS!MTB"
        threat_id = "2147960464"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SalatStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {4d 01 d3 44 01 d1 44 01 d2 45 01 d0 49 ff c2 49 0f af fa 48 01 de 49 d3 c3 89 d1 48 d3 cf 44 89 c1 48 d3 c6 49 31 fb 48 31 f7 48 81 f6 ?? ?? ?? ?? 48 ff cb eb}  //weight: 6, accuracy: Low
        $x_1_2 = "svchostdwmaudiodgsearchindexer''Add-MpPreference -ExclusionPath '' -Force" ascii //weight: 1
        $x_1_3 = "searchindexer''Add-MpPreference -ExclusionPath '' -Force" ascii //weight: 1
        $x_1_4 = "APPDATAProgramDataMicrosoftWindowsSecurityC:\\ProgramDataC:\\Users\\Public" ascii //weight: 1
        $x_1_5 = "HDUILPGT\\\\Bxrgdhdui\\\\Lxcsdlh!Stutcstg\\\\Tmrajhxdch\\\\EpiwhAPPDATAProgramDataMicrosoftWindowsSecurityC:\\ProgramDataC:\\Users\\Public" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_6_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_SalatStealer_ASL_2147961689_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SalatStealer.ASL!MTB"
        threat_id = "2147961689"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SalatStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 14 01 83 f2 55 88 14 08 48 ff c1 48 39 cb 7f ee 48 89 d9 48 89 c3 31 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_SalatStealer_SS_2147961906_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SalatStealer.SS!MTB"
        threat_id = "2147961906"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SalatStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 4c 24 50 c7 44 24 20 40 00 00 00 31 d2 4d 89 f0 41 b9 00 30 00 00 e8 a9 b3 01 00 48 85 c0 0f 84 40 01 00 00 49 89 c7 48 8d 84 24 10 01 00 00 48 83 20 00 41 b9 00 10 00 00 4c 39 ce 4c 0f 42 ce 48 8b 4c 24 50 48 89 44 24 20 4c 89 fa 49 89 f8 e8 75 b3 01 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_SalatStealer_ASLT_2147963355_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SalatStealer.ASLT!MTB"
        threat_id = "2147963355"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SalatStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {01 d0 0f b6 c0 89 85 b0 00 00 00 8b 85 bc 00 00 00 48 63 d0 48 8b 85 e0 00 00 00 48 01 d0 44 0f b6 00 8b 85 b0 00 00 00 48 98 0f b6 4c 05 a0 8b 85 bc 00 00 00 48 63 d0 48 8b 85 e0 00 00 00 48 01 d0 44 89 c2 31 ca 88 10}  //weight: 2, accuracy: High
        $x_1_2 = {48 89 42 38 48 8b 85 d0 03 00 00 4c 8b 40 28 48 8b 85 d0 03 00 00 48 8b 00 48 8d 15 ?? ?? ?? ?? 48 89 c1 41 ff d0 48 8b 95 d0 03 00 00 48 89 42 40 48 8b 85 d0 03 00 00 4c 8b 40 28 48 8b 85 d0 03 00 00 48 8b 00 48 8d 15 ?? ?? ?? ?? 48 89 c1 41 ff d0 48 8b 95 d0 03 00 00 48 89 42 48 48 8b 85 d0 03 00 00 4c 8b 40 28 48 8b 85 d0 03 00 00 48 8b 00 48 8d 15 ?? ?? ?? ?? 48 89 c1 41 ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

