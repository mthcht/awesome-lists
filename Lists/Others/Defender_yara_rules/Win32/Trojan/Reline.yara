rule Trojan_Win32_Reline_FSB_2147787339_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Reline.FSB!MTB"
        threat_id = "2147787339"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Reline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://a0551002.xsph.ru" ascii //weight: 1
        $x_1_2 = "C:\\Users\\Administrator\\Desktop\\cryptor\\loader runpe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Reline_AMH_2147788179_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Reline.AMH!MTB"
        threat_id = "2147788179"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Reline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "JohnDoe\\Start Menu\\Programs" ascii //weight: 3
        $x_3_2 = "%%P:hidcon:" ascii //weight: 3
        $x_3_3 = "svchost.cmd" ascii //weight: 3
        $x_3_4 = "@InstallEnd@!" ascii //weight: 3
        $x_3_5 = "Enter password" ascii //weight: 3
        $x_3_6 = "!Require Windows" ascii //weight: 3
        $x_3_7 = "GetNativeSystemInfo" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Reline_AM_2147789169_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Reline.AM!MTB"
        threat_id = "2147789169"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Reline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 39 8e e3 38 8d b5 ?? ?? ?? ?? f7 e7 8b c7 03 f7 c1 ea 02 8d 0c ?? 03 c9 2b c1 [0-24] 30 06 b8 39 8e e3 38 f7 e1 8b c7 83 c7 02 c1 ea 02 8d 0c ?? 03 c9 2b c1 0f b6 80 ?? ?? ?? ?? 30 46 01 81 ff 7e 07 00 00 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Reline_AWC_2147797016_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Reline.AWC!MTB"
        threat_id = "2147797016"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Reline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Panasonic Eneloop Pro 2xAA 2500 mAh" ascii //weight: 1
        $x_1_2 = "210908150437" ascii //weight: 1
        $x_1_3 = "310909150437" ascii //weight: 1
        $x_1_4 = "1.2.156.56359" wide //weight: 1
        $x_1_5 = "New Jersey" ascii //weight: 1
        $x_1_6 = "Greater Manchester" ascii //weight: 1
        $x_1_7 = "Salford" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Reline_RA_2147808752_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Reline.RA!MTB"
        threat_id = "2147808752"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Reline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GASfdrtwyefdeytwr" ascii //weight: 1
        $x_1_2 = "GFASrtefdwtrdwe" ascii //weight: 1
        $x_1_3 = "bZGtARYPF\\AeWG5" ascii //weight: 1
        $x_1_4 = "GetLocaleInfoEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Reline_RT_2147809868_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Reline.RT!MTB"
        threat_id = "2147809868"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Reline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d f1 82 e0 be 75 ?? 0f b6 45 ?? 89 45 ?? 8b 45 ?? 03 45 ?? 89 45 ?? 8b 45 ?? 0f b6 00 88 45 ?? b8 b8 8b 14 bf}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Reline_RTA_2147809869_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Reline.RTA!MTB"
        threat_id = "2147809869"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Reline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {29 c2 f7 d8 0f b6 14 11 b9 ?? ?? ?? ?? 88 94 07 ?? ?? ?? ?? b8 1e 92 dd 2e 2b 45 ?? 29 c1 b8 b4 d0 0c 1b 89 4d ?? 3d 4d e0 b1 13 7e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Reline_RM_2147811333_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Reline.RM!MTB"
        threat_id = "2147811333"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Reline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 ec 08 8b 5d ?? 8b 7d ?? 8b 75 ?? b8 47 68 9c a9 89 5d ?? 81 c3 b0 00 00 00 3d 47 68 9c a9 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Reline_RW_2147811335_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Reline.RW!MTB"
        threat_id = "2147811335"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Reline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 c3 8b 45 ?? 09 d9 88 08 b8 e0 6b 7a 96 3d c4 1f 36 d7 7f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Reline_RWA_2147811336_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Reline.RWA!MTB"
        threat_id = "2147811336"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Reline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 77 6e 7a 70 75 ?? 8b 45 ?? 0f b6 04 06 89 45 ?? 8b 45 ?? 01 c8 89 45 ?? b8 db 35 2d b0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Reline_RWB_2147811337_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Reline.RWB!MTB"
        threat_id = "2147811337"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Reline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 93 2d f1 eb 0f [0-5] 8b 45 [0-4] b9 f8 8c b7 88 88 45 ?? 0f b6 45 ?? 89 [0-5] 8b [0-5] 83 [0-5] 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

