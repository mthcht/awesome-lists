rule Trojan_Win32_GraceWire_2147749714_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GraceWire!dha"
        threat_id = "2147749714"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GraceWire"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "reselling-corp.com" wide //weight: 3
        $x_1_2 = "shutdown /r /t" ascii //weight: 1
        $x_1_3 = "Cookie:" wide //weight: 1
        $x_1_4 = "Failed to open the target process" ascii //weight: 1
        $x_1_5 = "Failed to inject the DLL" ascii //weight: 1
        $x_2_6 = "getandgodll_Win32.dll" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_GraceWire_BL_2147750251_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GraceWire.BL!dha"
        threat_id = "2147750251"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GraceWire"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c7 45 fc 00 00 00 00 8b 45 08 33 45 0c 89 45 08 c1 45 08 04 8b 4d 08 81 c1 78 77 77 77 89 4d 08 8b 45 08}  //weight: 2, accuracy: High
        $x_1_2 = {c7 45 fc 00 00 00 00 8b 45 08 33 45 0c 89 45 08 c1 45 08 04 8b 4d 08 81 c1 ?? ?? ?? ?? 89 4d 08 8b 45 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

