rule Trojan_Win32_DistTrack_A_2147731181_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DistTrack.A"
        threat_id = "2147731181"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DistTrack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 8b 08 83 c0 02 66 85 c9 75 f5 2b c2 d1 f8 8b f0 33 c9 8d 46 01 ba 02 00 00 00 f7 e2 0f 90 c1 f7 d9 0b c8 51 e8 f1 a2 00 00 33 c9 83 c4 04 66 89 0c 70 85 f6 74 16 8b d7 8b c8 2b d0}  //weight: 1, accuracy: High
        $x_1_2 = {e8 d3 e6 ff ff bb 11 00 00 00 b8 ?? ?? ?? ?? e8 e4 be ff ff 8d 4c 24 20 51 89 44 24 24 c7 44 24 28 ?? ?? ?? ?? 89 7c 24 2c 89 7c 24 30 ff 15 ?? ?? ?? ?? 85 c0 75 36}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DistTrack_B_2147731267_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DistTrack.B"
        threat_id = "2147731267"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DistTrack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/c copy  net" wide //weight: 1
        $x_1_2 = "\\admin$\\process.bat" wide //weight: 1
        $x_1_3 = "Spreader.exe" ascii //weight: 1
        $x_1_4 = "/c spreader.exe A" wide //weight: 1
        $x_1_5 = "cmd.exe?/c spreader.exe" wide //weight: 1
        $x_1_6 = "*.txt?shutter" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_DistTrack_C_2147731412_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DistTrack.C"
        threat_id = "2147731412"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DistTrack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 d2 8b c1 f7 75 14 8b 45 10 8d 34 39 41 8a 14 02 8b 45 fc 32 14 30 88 16 3b cb 72 e3}  //weight: 1, accuracy: High
        $x_1_2 = {66 8b 3c 0a 66 03 fb 66 89 39 83 c1 02 4e 75 f0}  //weight: 1, accuracy: High
        $x_1_3 = {66 8b 4d 0c 66 01 0c 46 40 3b c7 72 f3}  //weight: 1, accuracy: High
        $x_1_4 = {80 04 30 e0 40 83 f8 12 72 f6}  //weight: 1, accuracy: High
        $x_2_5 = "r~~zD99/}/}I/}G/}" wide //weight: 2
        $x_2_6 = "a[hd[b)($Zbb" wide //weight: 2
        $x_2_7 = "iv{sizqz{v" wide //weight: 2
        $x_1_8 = "[WN\\_IZMdUqkzw{wn|d_qvlw" wide //weight: 1
        $x_1_9 = "mz{qwvdXwtqkqm{d[" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

