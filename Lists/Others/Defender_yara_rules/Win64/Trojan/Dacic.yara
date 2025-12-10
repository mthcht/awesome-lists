rule Trojan_Win64_Dacic_ADA_2147906287_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dacic.ADA!MTB"
        threat_id = "2147906287"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dacic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4c 03 c0 66 90 b8 9d 82 97 53 4d 8d 40 01 f7 e9 c1 fa 04 8b c2 c1 e8 1f 03 d0 0f be c2 6b d0 31 0f b6 c1 ff c1 2a c2 04 30 41 30 40 ff 83 f9 0c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dacic_ADC_2147906302_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dacic.ADC!MTB"
        threat_id = "2147906302"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dacic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 03 c0 66 66 0f 1f 84 00 ?? ?? ?? ?? b8 93 24 49 92 4d 8d 40 01 f7 e9 03 d1 c1 fa 05 8b c2 c1 e8 1f 03 d0 0f be c2 6b d0 38 0f b6 c1 ff c1 2a c2 04 36 41 30 40 ff 83 f9 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dacic_ADI_2147906308_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dacic.ADI!MTB"
        threat_id = "2147906308"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dacic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4d 63 c8 4d 03 ca 0f 1f 40 00 66 0f 1f 84 00 00 00 00 00 b8 ?? ?? ?? ?? 41 f7 e8 41 03 d0 c1 fa 05 8b c2 c1 e8 1f 03 d0 0f be c2 6b c8 39 41 0f b6 c0 2a c1 04 34 41 30 01 41 ff c0 4d 8d 49 01 41 83 f8 41}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dacic_ADJ_2147906328_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dacic.ADJ!MTB"
        threat_id = "2147906328"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dacic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 63 c1 4c 8d 44 24 20 4c 03 c0 66 90 b8 1f 85 eb 51 4d 8d 40 01 f7 e9 c1 fa 04 8b c2 c1 e8 1f 03 d0 0f be c2 6b d0 32 0f b6 c1 ff c1 2a c2 04 33 41 30 40 ff 83 f9 0c 7c d3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dacic_RK_2147906496_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dacic.RK!MTB"
        threat_id = "2147906496"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dacic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8d 42 c3 30 44 15 e0 48 ff c2 48 83 fa 0d 72 f0}  //weight: 5, accuracy: High
        $x_1_2 = "Normaliz.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dacic_WE_2147907065_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dacic.WE!MTB"
        threat_id = "2147907065"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dacic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "arctic.pdb" ascii //weight: 1
        $x_1_2 = "start cmd /C \"color b && title Error && echo" ascii //weight: 1
        $x_1_3 = "certutil -hashfile " ascii //weight: 1
        $x_1_4 = "&& timeout /t 5" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dacic_RPX_2147907701_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dacic.RPX!MTB"
        threat_id = "2147907701"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dacic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b8 95 20 4f 09 f7 e9 d1 fa 8b c2 c1 e8 1f 03 d0 0f be c2 6b d0 37 0f b6 c1 2a c2 04 39 41 30 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dacic_RPX_2147907701_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dacic.RPX!MTB"
        threat_id = "2147907701"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dacic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f7 e9 d1 fa 8b c2 c1 e8 1f 03 d0 0f be c2 6b d0 37 0f b6 c1 2a c2 04 39 41 30 00 ff c1 4d 8d 40 01 83 f9 19}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dacic_MKV_2147907846_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dacic.MKV!MTB"
        threat_id = "2147907846"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dacic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 ef 03 d7 c1 fa 05 8b c2 c1 e8 1f 03 d0 0f be c2 6b c8 38 40 0f b6 c7 2a c1 04 36 41 30 00 ff c7 4d 8d 40 ?? 83 ff 27 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dacic_ADZ_2147909778_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dacic.ADZ!MTB"
        threat_id = "2147909778"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dacic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 41 b8 00 80 00 00 49 8b cc ff 15 ?? ?? ?? ?? 8b 55 df 33 c9 44 8d 49 04 41 b8 00 30 00 00 ff 15 ?? ?? ?? ?? 4c 8b e0 4c 8d 4d df 44 8b 45 df 48 8b d0 b9 0b 00 00 00 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dacic_RR_2147910292_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dacic.RR!MTB"
        threat_id = "2147910292"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dacic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b c8 ff 15 ?? ?? ?? ?? 48 8b 5d ?? 48 2b 5d ?? 48 c1 fb 05 ff 15 ?? ?? ?? ?? 48 98 33 d2 48 f7 f3 48 63 d2 48 c1 e2 05 48 03 55 ?? 48 8d 8d ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dacic_AMAK_2147915536_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dacic.AMAK!MTB"
        threat_id = "2147915536"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dacic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b0 01 48 83 c4 38 c3 cc cc cc cc 80 79 05 00 74 1d 33 c0 0f 1f 84 00 00 00 00 00 8d 50 eb 30 14 01 48 ff c0 48 83 f8 04 72 f1 c6 41 05 00 48 8b c1 c3}  //weight: 1, accuracy: High
        $x_1_2 = {74 20 0f 1f 40 00 66 0f 1f 84 00 00 00 00 00 8d 48 eb 30 0c 02 48 ff c0 48 83 f8 07 72 f1 c6 42 08 00 4c 8d 42 07 48 8b cb 4c 8d 4c 24 48 e8 ?? ?? ?? ?? 48 8b c3 48 83 c4 30 5b c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Dacic_ARZ_2147920366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dacic.ARZ!MTB"
        threat_id = "2147920366"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dacic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {f7 eb d1 fa 8b c2 c1 e8 1f 03 d0 0f be c2 6b c8 37 0f b6 c3 2a c1 04 38 41 30 00 ff c3 4d 8d 40 01 83 fb 41 7c d5}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dacic_NE_2147922730_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dacic.NE!MTB"
        threat_id = "2147922730"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dacic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {49 ff ca b8 cd cc cc cc 41 f7 e0 c1 ea 03 0f b6 c2 c0 e0 02 8d 0c 10 02 c9 44 2a c1 41 80 c0 30 45 88 02 44 8b c2 85 d2 75 d6}  //weight: 3, accuracy: High
        $x_2_2 = {f7 e9 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 0f be c2 6b d0 ?? 0f b6 c1 2a c2 04 30 41 30 ?? ff c1 4d 8d 40 ?? 83 f9 1d 7c}  //weight: 2, accuracy: Low
        $x_1_3 = {5c 00 78 00 36 00 34 00 5c 00 52 00 65 00 6c 00 65 00 61 00 73 00 65 00 5c 00 [0-47] 2e 00 70 00 64 00 62 00}  //weight: 1, accuracy: Low
        $x_1_4 = {5c 78 36 34 5c 52 65 6c 65 61 73 65 5c [0-47] 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Dacic_DZ_2147925073_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dacic.DZ!MTB"
        threat_id = "2147925073"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dacic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "certutil -hashfile" ascii //weight: 2
        $x_2_2 = "&& timeout /t 5" ascii //weight: 2
        $x_2_3 = "start cmd /C \"color b && title Error && echo" ascii //weight: 2
        $x_1_4 = "[ - ] LOADING HWID : WANNACRY" ascii //weight: 1
        $x_1_5 = "WANNACRY.exe" ascii //weight: 1
        $x_1_6 = "taskkill /f /im KsDumper.exe >nul 2>&1" ascii //weight: 1
        $x_1_7 = "\\\\.\\kprocesshacker" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Dacic_WWZ_2147925208_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dacic.WWZ!MTB"
        threat_id = "2147925208"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dacic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {f7 e1 8b c1 2b c2 d1 e8 03 c2 c1 e8 05 0f be c0 6b d0 38 0f b6 c1 ff c1 2a c2 04 36 41 30 40 ?? 83 f9 0c 7c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dacic_THK_2147925954_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dacic.THK!MTB"
        threat_id = "2147925954"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dacic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {f7 eb 03 d3 c1 fa 05 8b c2 c1 e8 ?? 03 d0 0f be c2 6b c8 39 0f b6 c3 ff c3 2a c1 04 34 41 30 40 ff 83 fb 17 7c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dacic_MPF_2147928261_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dacic.MPF!MTB"
        threat_id = "2147928261"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dacic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {41 f7 e0 c1 ea 05 0f be c2 6b c8 3a 41 0f b6 c0 2a c1 04 33 41 30 01 41 ff c0 4d 8d 49 ?? 41 83 f8 04 7c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dacic_TFZ_2147928977_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dacic.TFZ!MTB"
        threat_id = "2147928977"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dacic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {f7 e9 03 d1 c1 fa 05 8b c2 c1 e8 1f 03 d0 0f be c2 6b d0 ?? 0f b6 c1 ff c1 2a c2 04 36 41 30 40 ff 83 f9 1d 7c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dacic_OOZ_2147929145_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dacic.OOZ!MTB"
        threat_id = "2147929145"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dacic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {41 f7 e8 41 03 d0 c1 fa 05 8b c2 c1 e8 ?? 03 d0 0f be c2 6b c8 3a 41 0f b6 c0 2a c1 04 31 41 30 01 41 ff c0 4d 8d 49 01 41 83 f8 0c 7c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dacic_LOZ_2147929169_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dacic.LOZ!MTB"
        threat_id = "2147929169"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dacic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {41 f7 e8 41 03 d0 c1 fa 05 8b c2 c1 e8 1f 03 d0 0f be c2 6b c8 33 41 0f b6 c0 2a c1 04 37 41 30 01 41 ff c0 4d 8d 49 ?? 41 83 f8 1d 7c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dacic_NTJ_2147929303_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dacic.NTJ!MTB"
        threat_id = "2147929303"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dacic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {41 f7 e8 c1 fa 04 8b c2 c1 e8 1f 03 d0 0f be c2 6b c8 ?? 41 0f b6 c0 2a c1 04 38 41 30 01 41 ff c0 4d 8d 49 ?? 41 83 f8 1c 7c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dacic_AMCY_2147930694_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dacic.AMCY!MTB"
        threat_id = "2147930694"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dacic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {66 66 0f 1f 84 00 00 00 00 00 b8 ?? ?? ?? ?? 4d 8d 40 01 f7 e9 d1 fa 8b c2 c1 e8 1f 03 d0 0f be c2 6b d0 37 0f b6 c1 ff c1 2a c2 04 35 41 30 40 ff 83 f9 1d 7c}  //weight: 3, accuracy: Low
        $x_1_2 = "taskkill.exe /f" ascii //weight: 1
        $x_1_3 = "Zc_AntiHitbox" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dacic_AMCZ_2147930985_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dacic.AMCZ!MTB"
        threat_id = "2147930985"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dacic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {f7 e9 c1 fa 04 8b c2 c1 e8 1f 03 d0 0f be c2 6b d0 35 0f b6 c1 ff c1 2a c2 04 36 41 30 40 ff 83 f9 1d}  //weight: 5, accuracy: High
        $x_2_2 = "taskkill /FI \"IMAGENAME eq wireshark*\" /IM * /F /T >nul 2>&1" ascii //weight: 2
        $x_2_3 = "taskkill /FI \"IMAGENAME eq processhacker*\" /IM * /F /T >nul 2>&1" ascii //weight: 2
        $x_1_4 = "sc stop KProcessHacker2 >nul 2>&1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dacic_UTD_2147934739_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dacic.UTD!MTB"
        threat_id = "2147934739"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dacic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {41 f7 e8 c1 fa 04 8b c2 c1 e8 1f 03 d0 0f be c2 6b c8 34 41 0f b6 c0 2a c1 04 39 41 30 01 41 ff c0 4d 8d 49 01 41 83 f8 41 7c d0}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dacic_SEC_2147942173_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dacic.SEC!MTB"
        threat_id = "2147942173"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dacic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "*u9JmmX*LFD9D1" ascii //weight: 2
        $x_1_2 = "tV#*vV9i4ex6zW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dacic_C_2147945427_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dacic.C!MTB"
        threat_id = "2147945427"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dacic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "app_bound_encrypted_key" ascii //weight: 2
        $x_2_2 = "chrome_appbound_key.txt" ascii //weight: 2
        $x_2_3 = "SELECT host_key, name, encrypted_value FROM cookies;" ascii //weight: 2
        $x_2_4 = "SELECT origin_url, username_value, password_value FROM logins;" ascii //weight: 2
        $x_2_5 = "SELECT guid, name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards;" ascii //weight: 2
        $x_1_6 = "ReflectiveLoader" ascii //weight: 1
        $x_1_7 = "User Data" ascii //weight: 1
        $x_1_8 = "Login Data" ascii //weight: 1
        $x_1_9 = "chrome_decrypt.log" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dacic_GXU_2147952345_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dacic.GXU!MTB"
        threat_id = "2147952345"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dacic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {45 8a 08 41 0f be c9 66 41 89 ca 89 84 24 ?? ?? ?? ?? 44 8a 4c 24 ?? 41 80 e1 ?? 44 88 8c 24 ?? ?? ?? ?? 66 44 89 54 54 ?? 48 8b 94 24 ?? ?? ?? ?? 48 83 c2 ?? 48 89 94 24 ?? ?? ?? ?? 66 44 8b 54 24 ?? 66 41 81 f2 ?? ?? 66 44 89 94 24 ?? ?? ?? ?? 48 83 fa}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dacic_AHB_2147956311_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dacic.AHB!MTB"
        threat_id = "2147956311"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dacic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {48 33 d1 48 b9 ?? ?? ?? ?? ?? ?? ?? ?? 48 8b c2 48 c1 e0 ?? 48 33 c2 48 33 c1 48 89 43 ?? 0f 31 48 c1 e2 ?? 48 8d 4d 10 48 0b c2 48 33 c1}  //weight: 30, accuracy: Low
        $x_20_2 = {0f b6 c8 48 8d 46 ?? 8b e9 48 0f 44 de 83 f5 ?? 84 c9 48 0f 44 c6 48 8b 30 44 38 66 19 74}  //weight: 20, accuracy: Low
        $x_10_3 = "msedge.crashpad_%u_%04X" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Dacic_AHB_2147956311_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dacic.AHB!MTB"
        threat_id = "2147956311"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dacic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {48 33 d1 48 b9 ?? ?? ?? ?? ?? ?? ?? ?? 48 8b c2 48 c1 e0 ?? 48 33 c2 48 33 c1 48 89 43 ?? 0f 31 48 c1 e2 ?? 48 8d 4d 10 48 0b c2 48 33 c1}  //weight: 30, accuracy: Low
        $x_20_2 = "WARNING: Analysis environment detected" ascii //weight: 20
        $x_10_3 = "Obfuscation may be compromised" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

