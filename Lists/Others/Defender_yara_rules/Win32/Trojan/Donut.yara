rule Trojan_Win32_Donut_CB_2147839731_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Donut.CB!MTB"
        threat_id = "2147839731"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Donut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "gnirtSdaolnwoD" wide //weight: 1
        $x_1_2 = "gnirtS46esaBmorF" wide //weight: 1
        $x_1_3 = "CyberSECx/RTK_Adv_DInvoke_B64_Binary" wide //weight: 1
        $x_1_4 = "Cyberdyne" wide //weight: 1
        $x_1_5 = "peelS" wide //weight: 1
        $x_1_6 = "SM_LASTSM_x64.exe" ascii //weight: 1
        $x_1_7 = "T3PR94FN" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Donut_AMAB_2147853389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Donut.AMAB!MTB"
        threat_id = "2147853389"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Donut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b f3 2b fb 8b e9 8a 04 37 30 06 46 83 ed 01}  //weight: 1, accuracy: High
        $x_1_2 = {03 cf 03 c6 c1 c7 05 33 f9 c1 c6 08 33 f0 c1 c1 10 03 c7 03 ce c1 c7 07 c1 c6 0d 33 f8 33 f1 c1 c0 10 83 6c 24 30 01 75 d7 8b 6c 24 28 89 4c 24 14 33 c9 89 74 24 20 89 7c 24 18 89 44 24 1c 8b 44 8d 00 31 44 8c 14 41 83 f9 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Donut_YAB_2147945877_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Donut.YAB!MTB"
        threat_id = "2147945877"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Donut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {b8 68 58 4d 56 bb 00 00 00 00 b9 0a 00 00 00 ba 58 56 00 00 ed 81 fb 68 58 4d 56 0f 94 45 e7}  //weight: 5, accuracy: High
        $x_1_2 = "schtasks /create /tn" ascii //weight: 1
        $x_1_3 = "djkggosj.bat" ascii //weight: 1
        $x_5_4 = {0f b6 cb 32 b9 ?? ?? ?? ?? 8a 6d ff 8a 48 f3 8d 70 04 8a 58 f4 32 cf 32 5d fe 42 88 48 03 8a 48 f5 32 4d fd 88 48 05 8a 48 f6 32 cd}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Donut_GZN_2147952146_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Donut.GZN!MTB"
        threat_id = "2147952146"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Donut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2b c6 d1 f8 03 c2 03 c7 6a 04 8d 74 18 01 68 00 10 00 00 8d 0c 36 51 6a 00 ff 15 ?? ?? ?? ?? 8b f8 85 f6}  //weight: 5, accuracy: Low
        $x_5_2 = {6a 00 6a 00 68 ?? ?? ?? ?? 8b f0 56 6a 00 ff 15 ?? ?? ?? ?? 68 00 80 00 00 6a 00 56 ff 15}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

