rule TrojanDropper_Win32_Bohu_A_2147641422_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Bohu.A"
        threat_id = "2147641422"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Bohu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/c netsh -c interface dump>" ascii //weight: 1
        $x_1_2 = {6e 65 74 73 68 20 69 6e 74 65 72 66 61 63 65 20 69 70 20 73 65 74 20 61 64 64 72 65 73 73 20 6e 61 6d 65 3d 22 fd a6 80 22 20 20 73 6f 75 72 63 65 3d 64 68 63 70}  //weight: 1, accuracy: High
        $x_1_3 = {2f 54 49 4d 45 4f 55 54 3d ?? 30 30 30 30 00 45 78 65 63 54 6f 4c 6f 67 00 ?? 30 30 30 00 73 6f 75 72 63 65 3d 73 74 61 74 69 63}  //weight: 1, accuracy: Low
        $x_1_4 = "svr.asp?t=uuplay&u=" ascii //weight: 1
        $x_1_5 = "msfsg.exe uncompress -s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Bohu_B_2147641801_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Bohu.B"
        threat_id = "2147641801"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Bohu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {81 38 4e 43 52 43 75 0e 8a 48 04 80 c9 20 80 f9 20 75 03 83 ce 04 81 78 fe 20 2f 44 3d}  //weight: 4, accuracy: High
        $x_1_2 = {75 6e 63 6f 6d 70 72 65 73 73 20 2d 73 20 ?? ?? ?? ?? ?? 2e 78 6d 6c 20 2d 64}  //weight: 1, accuracy: Low
        $x_1_3 = {2f 54 49 4d 45 4f 55 54 3d ?? 30 30 30 30 00 45 78 65 63 54 6f 4c 6f 67}  //weight: 1, accuracy: Low
        $x_1_4 = "svr.asp?t=uuplay&u=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Bohu_GNX_2147852655_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Bohu.GNX!MTB"
        threat_id = "2147852655"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Bohu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {41 00 f0 a1 41 00 9b a2 41 00 9b a2 41 00 1a a2 41 00 2a a2 41 00 9b a2 41 00 a4 a2 41 00 a4 a2 41 00 8e a1 41 00 8e a1 41 00 9c a1 41 00 9b a2 41 00 a6 a1 41 00 a6 a1 41 00 9b a2 41 00 9b a2 41 00 9b a2}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

