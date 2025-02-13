rule TrojanDropper_Win32_Dozmot_A_2147621255_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Dozmot.A"
        threat_id = "2147621255"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Dozmot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {68 f0 9b 5b 00 56 89 4c 24 30 ff d7 8b 1d ?? ?? ?? ?? 8d 54 24 24 6a 00 52 8d 44 24 1c 6a 0f 50 56 ff d3}  //weight: 2, accuracy: Low
        $x_2_2 = {68 24 ad 5b 00 56 89 54 24 30 ff d7 8d 44 24 24 6a 00 50 8d 4c 24 1c 6a 0f}  //weight: 2, accuracy: High
        $x_2_3 = {75 07 b8 24 ad 5b 00 eb 08 8b 44 24 10 85 c0 76}  //weight: 2, accuracy: High
        $x_1_4 = "DivxDecoder.DivxDecode" ascii //weight: 1
        $x_1_5 = {44 69 76 78 44 65 63 6f 64 65 00 48 6f 6f 6b 6f 66 66 00 48 6f 6f 6b 6f 6e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Dozmot_B_2147621658_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Dozmot.B"
        threat_id = "2147621658"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Dozmot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {75 05 bb f0 9b 5b 00}  //weight: 1, accuracy: High
        $x_1_2 = {75 07 bb 24 ad 5b 00 eb 04}  //weight: 1, accuracy: High
        $x_1_3 = {44 69 76 78 44 65 63 6f 64 65 72 2e 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDropper_Win32_Dozmot_C_2147626005_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Dozmot.C"
        threat_id = "2147626005"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Dozmot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 b9 ff 00 00 00 f7 f9 80 fa 61 7e 05 80 fa 7a 7c 0a}  //weight: 1, accuracy: High
        $x_2_2 = {80 f9 41 7c 0d 80 f9 4d 7f 08 0f be c9 83 c1 ?? eb 1f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Dozmot_D_2147638409_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Dozmot.D"
        threat_id = "2147638409"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Dozmot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 7d f4 00 10 40 00 0f 85 ?? ?? ?? ?? 6a 02 6a 00 6a f8}  //weight: 1, accuracy: Low
        $x_1_2 = {8b ce 83 ee 08 d3 ea 48 89 75 ?? 88 90 ?? ?? ?? ?? 79 e7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

