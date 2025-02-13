rule Trojan_Win32_RanumBot_KMG_2147754417_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RanumBot.KMG!MTB"
        threat_id = "2147754417"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RanumBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {d3 e2 89 5c 24 ?? 89 54 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? ?? 44 24 10 a1 ?? ?? ?? ?? 3d 1a 0c 00 00 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RanumBot_KMG_2147754417_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RanumBot.KMG!MTB"
        threat_id = "2147754417"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RanumBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {d3 e2 89 5c 24 ?? 89 54 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? ?? 44 24 10 a1 ?? ?? ?? ?? 3d 4a 04 00 00 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RanumBot_KMG_2147754417_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RanumBot.KMG!MTB"
        threat_id = "2147754417"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RanumBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 89 45 ?? 8b 45 ?? ?? 45 ?? 8b 45 ?? ?? f8 8b 45 ?? ?? c3 33 f8 81 3d ?? ?? ?? ?? f5 03 00 00 c7 05 ?? ?? ?? ?? 36 06 ea e9 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RanumBot_KMG_2147754417_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RanumBot.KMG!MTB"
        threat_id = "2147754417"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RanumBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {d3 e2 89 7c 24 ?? 89 54 24 ?? 8b 44 24 ?? ?? 44 24 ?? 8b 44 24 ?? ?? 44 24 ?? 8b 7c 24 ?? a1 ?? ?? ?? ?? 03 fb 3d 72 05 00 00 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RanumBot_MR_2147766411_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RanumBot.MR!MTB"
        threat_id = "2147766411"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RanumBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f3 c1 e6 ?? 03 75 ?? 8b fb c1 ef ?? 03 7d ?? 03 d3 33 f2 81 3d ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 75 ?? 8d 45 ?? 50 ff 15 ?? ?? ?? ?? 33 fe 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75 ?? 6a ?? 6a ?? 6a ?? ff 15 ?? ?? ?? ?? 8b 75 ?? 2b f7 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 89 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RanumBot_MS_2147770171_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RanumBot.MS!MTB"
        threat_id = "2147770171"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RanumBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d1 31 55 70 8b 4d 70 8d 85 ?? ?? ?? ?? e8 ?? ?? ?? ?? 81 3d [0-4] 26 04 00 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {33 d1 31 55 70 8b 4d 70 8d 85 ?? ?? ?? ?? 29 08 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RanumBot_2147770355_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RanumBot.MT!MTB"
        threat_id = "2147770355"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RanumBot"
        severity = "Critical"
        info = "MT: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "AuthenticateZanabazar_Square\\windefender.exe" ascii //weight: 1
        $x_1_2 = "report/app/vc.exe" ascii //weight: 1
        $x_1_3 = "\\WinMon\\patch.exe" ascii //weight: 1
        $x_1_4 = {46 69 6c 65 55 52 4c 20 73 74 72 69 6e 67 [0-9] 66 69 6c 65 5f 75 72 6c}  //weight: 1, accuracy: Low
        $x_1_5 = {52 75 6e 41 73 54 49 20 62 6f 6f 6c [0-9] 72 75 6e 61 73 74 69}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RanumBot_MU_2147781243_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RanumBot.MU!MTB"
        threat_id = "2147781243"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RanumBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 45 ec 83 [0-6] 8b [0-2] 33 [0-2] 89 [0-2] 8b [0-2] 33 [0-2] 89 [0-2] 8b [0-2] 29 [0-2] 8b [0-2] 2b [0-2] 89 [0-2] e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RanumBot_V_2147892335_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RanumBot.V!MTB"
        threat_id = "2147892335"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RanumBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Go build ID: \"-Ww_4qvWhPJu8Ea7G1nf/BszYvuhViAe01YNvMVTn/vIHkr31eYSCDY3IWLGrI/r2_WYb3gQ0nb07HPcUc7" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RanumBot_VI_2147895572_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RanumBot.VI!MTB"
        threat_id = "2147895572"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RanumBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Go build ID: \"WhjuQixTKldUrhUwXWbJ" ascii //weight: 1
        $x_1_2 = "aCFV2zU59E4adXT/SLOUgp0OoNoRnjQrzZbR/ljzesiH2sXYRz0h45Hwg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

