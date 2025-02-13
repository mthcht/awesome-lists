rule Trojan_Win32_NanoCore_VD_2147754936_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NanoCore.VD!MTB"
        threat_id = "2147754936"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NanoCore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 34 01 17 41 81 f9 ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NanoCore_VD_2147754936_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NanoCore.VD!MTB"
        threat_id = "2147754936"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NanoCore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 d2 81 c2 ?? ?? ?? ?? 80 34 01 ?? 41 39 d1 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NanoCore_VD_2147754936_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NanoCore.VD!MTB"
        threat_id = "2147754936"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NanoCore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 45 fc 41 39 d1 75 0b 00 c7 45 fc ?? ?? ?? ?? 80 34 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NanoCore_VD_2147754936_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NanoCore.VD!MTB"
        threat_id = "2147754936"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NanoCore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c0 41 89 [0-64] 39 d9 [0-64] 80 34 01}  //weight: 1, accuracy: Low
        $x_1_2 = {89 c0 41 89 [0-64] 39 d9 [0-64] 89 [0-64] 80 34 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_NanoCore_VD_2147754936_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NanoCore.VD!MTB"
        threat_id = "2147754936"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NanoCore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 f7 f6 85 d2 [0-64] 8b c3 03 c1 [0-64] 80 30 [0-64] 41}  //weight: 1, accuracy: Low
        $x_1_2 = {33 d2 f7 f3 85 d2 [0-64] 8b c6 03 c1 [0-64] b2 [0-64] 30 10 [0-64] 41}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_NanoCore_VB_2147755652_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NanoCore.VB!MTB"
        threat_id = "2147755652"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NanoCore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "MSVBVM60.DLL" ascii //weight: 2
        $x_1_2 = "Hoernesite" wide //weight: 1
        $x_1_3 = "pertinaceous" wide //weight: 1
        $x_1_4 = "Kiselsyren4" wide //weight: 1
        $x_1_5 = "frisvmmer" wide //weight: 1
        $x_1_6 = "Pa09193" wide //weight: 1
        $x_1_7 = "SKURINGER" wide //weight: 1
        $x_1_8 = "Repipe" wide //weight: 1
        $x_1_9 = "Pargetted7" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NanoCore_VB_2147755652_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NanoCore.VB!MTB"
        threat_id = "2147755652"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NanoCore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "MSVBVM60.DLL" ascii //weight: 2
        $x_1_2 = "Nonflu5" wide //weight: 1
        $x_1_3 = "skyggerne" wide //weight: 1
        $x_1_4 = "Pygarg" wide //weight: 1
        $x_1_5 = "UNCOMPREHENSIBLENESS" wide //weight: 1
        $x_1_6 = "Aflagde" wide //weight: 1
        $x_1_7 = "ELECTROSTRICTIVE" wide //weight: 1
        $x_1_8 = "Surefootedness" wide //weight: 1
        $x_1_9 = "KRIGSGUDERNE" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NanoCore_VB_2147755652_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NanoCore.VB!MTB"
        threat_id = "2147755652"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NanoCore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "MSVBVM60.DLL" ascii //weight: 2
        $x_1_2 = "pigenavns" wide //weight: 1
        $x_1_3 = "Sidekicker4" wide //weight: 1
        $x_1_4 = "Sirenoid" wide //weight: 1
        $x_1_5 = "Sporangidium" wide //weight: 1
        $x_1_6 = "taarevaedet" wide //weight: 1
        $x_1_7 = "rentefordelens" wide //weight: 1
        $x_1_8 = "VERTEBROILIAC" wide //weight: 1
        $x_1_9 = "Hjemsendende9" wide //weight: 1
        $x_1_10 = "Confiscations" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NanoCore_RPG_2147821260_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NanoCore.RPG!MTB"
        threat_id = "2147821260"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NanoCore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {32 00 33 00 2e 00 32 00 32 00 39 00 2e 00 33 00 34 00 2e 00 31 00 31 00 34 00 3a 00 38 00 31 00 2f 00 [0-48] 2e 00 62 00 6d 00 70 00}  //weight: 1, accuracy: Low
        $x_1_2 = "Reverse" ascii //weight: 1
        $x_1_3 = "InvokeMember" ascii //weight: 1
        $x_1_4 = "Binder" ascii //weight: 1
        $x_1_5 = "ToArray" ascii //weight: 1
        $x_1_6 = "AddSeconds" ascii //weight: 1
        $x_1_7 = "IPStatus" ascii //weight: 1
        $x_1_8 = "HttpWebResponse" ascii //weight: 1
        $x_1_9 = "GetType" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NanoCore_RPW_2147832141_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NanoCore.RPW!MTB"
        threat_id = "2147832141"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NanoCore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2a c8 80 c1 2b 32 c8 fe c1 02 c8 c0 c1 02 32 c8 02 c8 32 c8 80 c1 6b 88 88 ?? ?? ?? ?? 40}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

