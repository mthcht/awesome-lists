rule Trojan_Win32_Wiessy_A_2147606800_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wiessy.A"
        threat_id = "2147606800"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wiessy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "SetThreadContext" ascii //weight: 5
        $x_5_2 = "WriteProcessMemory" ascii //weight: 5
        $x_1_3 = {5c 2a 73 74 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_2_4 = {50 68 00 e0 00 00 68 ?? ?? 40 00 e8 ?? ?? ff ff 85 c0 75 1c 83 c6 04 81 fe ?? ?? 41 00 0f 8c 49 ff ff ff 68 ?? ?? 40 00 e8 ?? ?? ff ff 83 c4 04 68 04 01 00 00}  //weight: 2, accuracy: Low
        $x_2_5 = {52 ff d6 85 c0 74 0a 81 7c 24 30 00 38 00 00 74 22 8d 44 24 10}  //weight: 2, accuracy: High
        $x_1_6 = {f3 a5 66 81 7c 24 ?? 4d 5a 75 54 8b 44 24 ?? 8d 48 18 3b d9 72 49 8b 0d ?? ?? ?? 00 8d 1c 01 03 da 8b d3 8b 02 8b 4a 04 89 44 24 ?? 8b 42 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Wiessy_B_2147606804_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wiessy.B"
        threat_id = "2147606804"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wiessy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s_qosec%d.msi" ascii //weight: 1
        $x_1_2 = "rrr: sp_minor = %d" ascii //weight: 1
        $x_1_3 = "execute file %s ." ascii //weight: 1
        $x_2_4 = "\\atielf.dat" ascii //weight: 2
        $x_2_5 = "krnl rik." ascii //weight: 2
        $x_2_6 = "ZwVdmControl" ascii //weight: 2
        $x_2_7 = "~wxp2ins." ascii //weight: 2
        $x_1_8 = "OllyDBG.EXE" ascii //weight: 1
        $x_1_9 = "idag.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

