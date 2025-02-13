rule Trojan_Win32_Malagent_PAA_2147777646_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Malagent.PAA!MTB"
        threat_id = "2147777646"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Malagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 42 5f 47 61 64 67 65 74 53 74 61 63 6b 5f [0-4] 69}  //weight: 1, accuracy: Low
        $x_1_2 = {43 3a 5c 54 45 4d 50 5c [0-4] 2e 74 6d 70}  //weight: 1, accuracy: Low
        $x_1_3 = "Debugger breakpoint reached" ascii //weight: 1
        $x_1_4 = "-NonI -W Hidden -Comman" ascii //weight: 1
        $x_1_5 = ".tmpb2etempfile" wide //weight: 1
        $x_1_6 = "ShellExecuteExA" ascii //weight: 1
        $x_1_7 = "RevokeDragDrop" ascii //weight: 1
        $x_1_8 = "SysIPAddress32" ascii //weight: 1
        $x_1_9 = "MDI_ChildClass" ascii //weight: 1
        $x_1_10 = "PB_Hotkey" ascii //weight: 1
        $x_1_11 = ".bat" ascii //weight: 1
        $x_1_12 = "\\\\?\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Malagent_PAC_2147809655_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Malagent.PAC!MTB"
        threat_id = "2147809655"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Malagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "schtasks.exe" ascii //weight: 1
        $x_1_2 = "123.253.33.211" ascii //weight: 1
        $x_1_3 = "RecordedTV\\RecordedTV.EXE" ascii //weight: 1
        $x_1_4 = "/F /Create /TN Microsoft_Corp /sc minute /MO 1 /TR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Malagent_RDB_2147838982_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Malagent.RDB!MTB"
        threat_id = "2147838982"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Malagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".bak" ascii //weight: 1
        $x_2_2 = {83 c4 04 33 c9 8b c5 ba 44 00 00 00 f7 e2 0f 90 c1 f7 d9 0b c8 33 c0 83 c1 04 0f 92 c0 f7 d8 0b c1 50 e8 ?? ?? ?? ?? 83 c4 04 89 44 24 48 3b c3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

