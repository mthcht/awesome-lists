rule Trojan_Win32_Bobik_ED_2147833988_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bobik.ED!MTB"
        threat_id = "2147833988"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bobik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2b 86 cc 00 00 00 2b 46 24 01 46 3c ff 46 48 8b 4e 48 8b 46 64 88 1c 01 b8 ?? ?? ?? ?? 2b 46 44 01 46 68 8b 96 ac 00 00 00 8b ae a0 00 00 00 8b c5 8b 5e 4c 33 c3}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bobik_EB_2147840081_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bobik.EB!MTB"
        threat_id = "2147840081"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bobik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 45 fc 0f b6 44 10 10 33 c8 66 3b ed 74 09}  //weight: 2, accuracy: High
        $x_2_2 = {8b 45 ec 03 45 f0 88 08 e9 49 01}  //weight: 2, accuracy: High
        $x_2_3 = {8b 45 ec 03 45 f0 0f b6 08 3a ed 74 86}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bobik_GMP_2147892754_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bobik.GMP!MTB"
        threat_id = "2147892754"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bobik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 c4 0c 8d 45 c4 50 c7 45 ?? 3c 00 00 00 c7 45 ?? 0c 00 00 00 c7 45 ?? a0 f9 40 00 c7 45 ?? e8 e4 40 00 c7 45 ?? 05 00 00 00 ff 15}  //weight: 10, accuracy: Low
        $x_10_2 = {56 57 68 b8 f9 40 00 33 ff ff 15}  //weight: 10, accuracy: High
        $x_1_3 = "FIHKXIHK" ascii //weight: 1
        $x_1_4 = "BYTrasTN1sTra" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bobik_NB_2147897389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bobik.NB!MTB"
        threat_id = "2147897389"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bobik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {64 89 20 8d 55 fc 8b c3 e8 7e 67 00 00 8b c7 8b ce 8b 55 ?? e8 c6 0d 00 00 33 c0 5a 59 59 64 89 10 68 65 9f}  //weight: 5, accuracy: Low
        $x_1_2 = "WWAN_AutoConfig.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bobik_ARA_2147952567_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bobik.ARA!MTB"
        threat_id = "2147952567"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bobik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {66 8b 02 8d 52 fe 0f b7 8c 75 34 ff ff ff 66 89 84 75 34 ff ff ff 46 66 89 4a 02 3b f7 7c e1}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

