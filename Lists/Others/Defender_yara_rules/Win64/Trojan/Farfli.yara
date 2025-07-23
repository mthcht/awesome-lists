rule Trojan_Win64_Farfli_MA_2147830927_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Farfli.MA!MTB"
        threat_id = "2147830927"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 d2 48 8d 0d ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 48 83 64 24 20 00 4c 8d 05 ?? ?? ?? ?? 45 33 c9 48 8d 15 ?? ?? ?? ?? 33 c9 ff 15}  //weight: 5, accuracy: Low
        $x_1_2 = "AlibabaisSB\\mian.exe" ascii //weight: 1
        $x_1_3 = "://43.142.187.203/" ascii //weight: 1
        $x_1_4 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_5 = "RtlCaptureContext" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Farfli_BAZ_2147848719_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Farfli.BAZ!MTB"
        threat_id = "2147848719"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {45 33 c9 45 33 c0 48 8b c8 4c 89 64 24 28 48 89 bc 24 88 04 00 00 c7 44 24 20 00 00 00 04 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {4c 89 64 24 30 45 33 c9 45 33 c0 ba 00 00 00 40 48 8b ce 44 89 64 24 28 c7 44 24 40 01 00 00 00 c7 44 24 20 02 00 00 00 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = "Users\\Public\\Documents\\NGLA" wide //weight: 1
        $x_1_4 = "ps.zip" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Farfli_RD_2147853019_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Farfli.RD!MTB"
        threat_id = "2147853019"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 0f b6 0c 11 45 8d 49 ff 30 0a 48 8d 52 ff 41 83 c0 ff 75 eb 41 8d 40 01 42 0f b6 04 10 43 30 04 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Farfli_CCAM_2147890126_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Farfli.CCAM!MTB"
        threat_id = "2147890126"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "8.217.113.145" wide //weight: 1
        $x_1_2 = "UnThreat.exe" wide //weight: 1
        $x_1_3 = "K7TSecurity.exe" wide //weight: 1
        $x_1_4 = "BitDefender" wide //weight: 1
        $x_1_5 = "NOD32" wide //weight: 1
        $x_1_6 = "QuickHeal" wide //weight: 1
        $x_1_7 = "F-Secure" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Farfli_GZZ_2147905929_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Farfli.GZZ!MTB"
        threat_id = "2147905929"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Windows\\Temp\\upgrader.back" ascii //weight: 1
        $x_1_2 = "api.buy3721.net" wide //weight: 1
        $x_1_3 = "64B46Ud5KMh6vqx7tZ8rx9DxX04s" ascii //weight: 1
        $x_1_4 = "wscript.exe //E:vbscript" ascii //weight: 1
        $x_1_5 = "baiduSafeTray.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Farfli_AFL_2147913099_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Farfli.AFL!MTB"
        threat_id = "2147913099"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 44 24 20 43 c6 44 24 21 3a c6 44 24 22 2f c6 44 24 23 55 c6 44 24 24 73 c6 44 24 25 65 c6 44 24 26 72 c6 44 24 27 73 c6 44 24 28 2f c6 44 24 29 50 c6 44 24 2a 75 c6 44 24 2b 62 c6 44 24 2c 6c c6 44 24 2d 69 c6 44 24 2e 63}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Farfli_AFA_2147924071_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Farfli.AFA!MTB"
        threat_id = "2147924071"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 8b 0b 41 b9 00 30 00 00 4c 8b c7 33 d2 48 89 b4 24 d0 06 00 00 c7 44 24 20 40 00 00 00 48 8b f7 ff 15 41 13 01 00 48 8b f8 48 85 c0 74 5a 48 8b 0b 4c 8b ce 4c 8b c5 48 8b d0 4c 89 64 24 20 ff 15 2a 13 01 00}  //weight: 2, accuracy: High
        $x_2_2 = {49 ff c1 b8 ef 23 b8 8f f7 e9 03 d1 c1 fa 08 8b c2 c1 e8 1f 03 d0 b8 cd cc cc cc 69 d2 c8 01 00 00 2b ca 41 f7 e2 80 c1 36 43 30 0c 03 c1 ea 03 8d 0c 92 03 c9 44 3b d1 4d 0f 44 cf 41 ff c2 49 ff c3 44 3b d7}  //weight: 2, accuracy: High
        $x_1_3 = "d33f351a4aeea5e608853d1a56661059" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Farfli_SDM_2147934110_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Farfli.SDM!MTB"
        threat_id = "2147934110"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {45 33 db 4c 8d 05 ?? ?? ?? ff 45 33 c9 4c 89 5c 24 28 33 d2 33 c9 44 89 5c 24 20 ff 15 ?? ?? ?? 00 83 ca ff 48 8b c8}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Farfli_ADC_2147941919_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Farfli.ADC!MTB"
        threat_id = "2147941919"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {2b ca 41 f7 e2 80 c1 36 43 30 0c 03 c1 ea 03 8d 0c 92 03 c9 44 3b d1 4d 0f 44 cf 41 ff c2 49 ff c3 44 3b d7 7c}  //weight: 4, accuracy: High
        $x_1_2 = {41 0f b6 0c 29 4c 8b 43 10 49 ff c1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Farfli_SXA_2147947305_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Farfli.SXA!MTB"
        threat_id = "2147947305"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Farfli"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {45 8b e7 4d 8b ef 45 85 db 7e 1d 4c 8b d5 41 0f b7 02 66 43 39 04 10 75 0f 4c 03 ea 44 03 e2 49 83 c2 02 4d 3b eb 7c e6 45 3b e3 74 0d 03 ca 49 83 c0 02 41 3b c9 7e c8}  //weight: 3, accuracy: High
        $x_2_2 = {41 0f b7 00 0f b7 0a 66 89 02 66 41 89 08 49 83 e8 02 48 83 c2 02 49 ff c9 75 e5}  //weight: 2, accuracy: High
        $x_1_3 = "d33f351a4aeea5e608853d1a56661059" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

