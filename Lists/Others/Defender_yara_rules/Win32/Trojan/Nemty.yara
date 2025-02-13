rule Trojan_Win32_Nemty_PB_2147743676_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nemty.PB!MTB"
        threat_id = "2147743676"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nemty"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "4E454D5459" wide //weight: 2
        $x_1_2 = "76737361646D696E2E6578652064656C65746520736861646F777320" wide //weight: 1
        $x_1_3 = "2F616C6C202F7175696574" wide //weight: 1
        $x_2_4 = "6675636B6176" wide //weight: 2
        $x_2_5 = "776D696320736861646F77636F70792064656C657465" wide //weight: 2
        $x_2_6 = "2D444543525950542E747874" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Nemty_PD_2147743744_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nemty.PD!MTB"
        threat_id = "2147743744"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nemty"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "mode" ascii //weight: 1
        $x_1_2 = "spsz" ascii //weight: 1
        $x_1_3 = "namesz" ascii //weight: 1
        $x_1_4 = "idsz" ascii //weight: 1
        $x_1_5 = "crmask" ascii //weight: 1
        $x_1_6 = "white" ascii //weight: 1
        $x_1_7 = "file" ascii //weight: 1
        $x_1_8 = "svcwait" ascii //weight: 1
        $x_1_9 = "mail" ascii //weight: 1
        $x_1_10 = "lend" ascii //weight: 1
        $x_1_11 = "lfile" ascii //weight: 1
        $x_1_12 = {5c 00 00 00 66 89 ?? ?? ?? 76 00 00 00 66 89 ?? ?? ?? 73 00 00 00 66 89 ?? ?? ?? 73 00 00 00 66 89 ?? ?? ?? 61 00 00 00 66 89 ?? ?? ?? 64 00 00 00 66 89 ?? ?? ?? 6d 00 00 00 66 89 ?? ?? ?? 69 00 00 00 66 89 ?? ?? ?? 6e 00 00 00 66 89 ?? ?? ?? 2e 00 00 00 66 89 ?? ?? ?? 65 00 00 00 66 89 ?? ?? ?? 78 00 00 00 66 89 ?? ?? ?? 65 00 00 00 66 89}  //weight: 1, accuracy: Low
        $x_1_13 = {b9 64 00 00 00 66 89 ?? ?? ?? 65 00 00 00 66 89 ?? ?? ?? 6c 00 00 00 66 89 ?? ?? ?? 65 00 00 00 66 89 ?? ?? ?? 74 00 00 00 66 89 ?? ?? ?? 65 00 00 00 66 89 ?? ?? ?? 20 00 00 00 66 89 ?? ?? ?? 73 00 00 00 66 89 ?? ?? ?? 68 00 00 00 66 89 ?? ?? ?? 61 00 00 00 66 89 ?? ?? ?? 64 00 00 00 66 89 ?? ?? ?? 6f 00 00 00 66 89 ?? ?? ?? 77 00 00 00 66 89 ?? ?? ?? 73 00 00 00 66 89 ?? ?? ?? 20 00 00 00 66 89}  //weight: 1, accuracy: Low
        $x_1_14 = {2f 00 00 00 66 89 ?? ?? ?? 61 00 00 00 66 89 ?? ?? ?? 6c 00 00 00 66 89 ?? ?? ?? 6c 00 00 00 66 89 ?? ?? ?? 20 00 00 00 66 89 ?? ?? ?? 2f 00 00 00 66 89 ?? ?? ?? 71 00 00 00 66 89 ?? ?? ?? 75 00 00 00 66 89 ?? ?? ?? 69 00 00 00 66 89 ?? ?? ?? 65 00 00 00 66 89 ?? ?? ?? 74 00 00 00 66 89}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Nemty_PE_2147743819_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nemty.PE!MTB"
        threat_id = "2147743819"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nemty"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 1c 0a 8b c0 3b 4c 24 04 8b c0 7d 09 8b c0 83 c1 04 8b c0 eb ea}  //weight: 1, accuracy: High
        $x_1_2 = {33 c0 8a 83 ?? ?? ?? ?? 2b c3 40 8b c8 83 e0 01 d1 e9 83 e1 7f c1 e0 07 0b c8 8d 44 59 53 33 c3 8b d0 c1 ea 04 80 e2 0f c0 e0 04 0a d0 fe c2 32 d3 f6 d2 02 d3 80 f2 ae 2a d3 fe c2 32 d3 80 f2 d4 2a d3 80 ea 6b 88 93 ?? ?? ?? ?? 43 81 fb ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Nemty_PA_2147786354_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nemty.PA!MTB"
        threat_id = "2147786354"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nemty"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {f5 11 00 00 75 0e 6a 00 ff 15 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 69 c9 ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 8b c1 89 0d ?? ?? ?? ?? c1 e8 10 30 04 ?? ?? 3b ?? 7c cb 02 00 81}  //weight: 4, accuracy: Low
        $x_1_2 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

