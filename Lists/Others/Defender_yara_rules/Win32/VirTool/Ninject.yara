rule VirTool_Win32_Ninject_A_2147696916_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Ninject.A"
        threat_id = "2147696916"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Ninject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f be 14 10 33 ca 8b 85 ?? ?? ?? ?? 88 8c 05 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 83 c0 01}  //weight: 1, accuracy: Low
        $x_1_2 = {0f be 14 10 33 ca 8b 45 ?? 03 85 ?? ?? ?? ?? 88 08 8b 45 ?? 03 85 ?? ?? ?? ?? 0f be 08 8b 85 ?? ?? ?? ?? 99 f7 bd}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Ninject_B_2147696917_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Ninject.B"
        threat_id = "2147696917"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Ninject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 11 8b 95 ?? ?? ?? ?? 30 84 15 ?? ?? ?? ?? ff 85}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 04 11 8b 55 ?? 8b 8d ?? ?? ?? ?? 30 04 0a ff 85 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 99 f7 bd}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Ninject_C_2147696918_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Ninject.C"
        threat_id = "2147696918"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Ninject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 04 10 32 03 88 01 8d 85 ?? ?? ?? ?? ff}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 04 10 32 03 88 01 8b 45 ?? 8b 8d ?? ?? ?? ?? 01 c1 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 99 f7 3e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Ninject_D_2147697039_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Ninject.D"
        threat_id = "2147697039"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Ninject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 10 8b 85 ?? ?? ?? ?? 30 94 28 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? ff 85}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 00 32 02 88 c2 8b 85 ?? ?? ?? ?? 03 85 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 99 f7 bd}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Ninject_E_2147697041_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Ninject.E"
        threat_id = "2147697041"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Ninject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 c1 88 cb 8b ?? ?? ?? ?? ?? ?? 8b ?? ?? ?? ?? ?? ?? 88 1c 01 8b ?? ?? ?? ?? ?? ?? 83 c0 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Ninject_F_2147697293_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Ninject.F"
        threat_id = "2147697293"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Ninject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 04 11 ff 45 fc 8b 45 fc 3b 45 14}  //weight: 1, accuracy: High
        $x_1_2 = {32 04 0a 8b ?? ?? ?? ?? ?? 8b ?? ?? ?? ?? ?? 88 04 0a c7 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Ninject_G_2147697304_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Ninject.G"
        threat_id = "2147697304"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Ninject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 d0 8a 10 8b 85 ?? ?? ?? ?? 30 94 ?? ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 00 32 02 88 c2 8b 85 ?? ?? ?? ?? 03 85 ?? ?? ?? ?? 88 10 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Ninject_H_2147706289_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Ninject.H"
        threat_id = "2147706289"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Ninject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 f7 fe 88 44 0d ?? 0f bf [0-24] 99 f7}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 04 0a 30 84 2b [0-10] 99 f7}  //weight: 1, accuracy: Low
        $x_1_3 = {32 0c 02 88 ?? ?? ?? ?? ?? 88 0f [0-10] 99 f7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

