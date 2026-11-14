rule Trojan_Win32_RemusStealer_SL_2147975254_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RemusStealer.SL!MTB"
        threat_id = "2147975254"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RemusStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4e 89 24 da 4e 8b 1c d8 4d 0f af dd 4c 01 ee 4f 8d 14 5a eb 53 4a c7 04 da 00 00 00 00 4e 8b 1c d8}  //weight: 1, accuracy: High
        $x_1_2 = "main.nwpryqfxbwwrd" ascii //weight: 1
        $x_1_3 = "main.ehayvkthxbtozsuk" ascii //weight: 1
        $x_1_4 = "main.affayccuimjlbdnqgw" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RemusStealer_GV_2147978297_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RemusStealer.GV!MTB"
        threat_id = "2147978297"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RemusStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 48 b1 32 4c 04 20 80 c1 9e 88 4c 04 20 48 ff c0 48 83 f8 0c 75 e9}  //weight: 1, accuracy: High
        $x_1_2 = "GetClipboardData" ascii //weight: 1
        $x_1_3 = "GetClipboardSequenceNumber" ascii //weight: 1
        $x_1_4 = "OpenClipboard" ascii //weight: 1
        $x_1_5 = "SetClipboardData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RemusStealer_2147978811_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RemusStealer!atmn"
        threat_id = "2147978811"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RemusStealer"
        severity = "Critical"
        info = "atmn: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "crtloader/caller_go/payload.LoadPacked" ascii //weight: 1
        $x_1_2 = "crtloader/caller_go/native.PreparePayloadIO" ascii //weight: 1
        $x_1_3 = "crtloader/caller_go/sysc.isHookedStub" ascii //weight: 1
        $x_1_4 = "I:/11DD/caller-master/payload/selfload.go" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RemusStealer_2147978811_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RemusStealer!atmn"
        threat_id = "2147978811"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RemusStealer"
        severity = "Critical"
        info = "atmn: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "%s~st%08X.xml" wide //weight: 3
        $x_2_2 = "<description>Desktop Application Runtime</description>" ascii //weight: 2
        $x_1_3 = "<Triggers><TimeTrigger><StartBoundary>" ascii //weight: 1
        $x_1_4 = "<Triggers><LogonTrigger><UserId>" ascii //weight: 1
        $x_1_5 = "<ExecutionTimeLimit>PT0S</ExecutionTimeLimit></Settings>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RemusStealer_M_2147981725_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RemusStealer.M!MTB"
        threat_id = "2147981725"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RemusStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HekZyoRtNCnA]heupOv" ascii //weight: 1
        $x_1_2 = {53 cc 42 ee ae 10 f4 32 cc 54 dc 76 c0 98 01 44 bd 88 3f cd c5 11 5b 56 ee 9a 27 df 1c 23 8b 67 3a ac c5 f0 e2 b0 37 61 6e 12 ce c2 04 73 69 24 a6 d4 1e 85 53 36 f6 e6 d6 97 5b 48 85 f8 e6 a9 36 5a 91 0a ed bb 2b 6c dd 1c e7 cd 3e 7e 73 2f 99 df 3b 90 63 41 a9 f1 07 a2 45 53 b4 03 e7 b4 11 65 b0 15 fd c6 51 77 9b 27 f5 d8 2f 89 9f 39 db ea 58 9b 95 66 cb cd 19 34 2f 9b 76 02 89 68 9e cf d3 36 0a 9d 46 04 69 6b b5 d1 cf 38 17 9f 2b 06 59 6d c3 d3 c4 3a 7f e1 83 34 f5 92 7b e5 a9 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

