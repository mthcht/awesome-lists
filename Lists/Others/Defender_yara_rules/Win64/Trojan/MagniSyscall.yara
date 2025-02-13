rule Trojan_Win64_MagniSyscall_A_2147848624_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/MagniSyscall.A"
        threat_id = "2147848624"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "MagniSyscall"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 33 c0 4c 8b d1 b8 18 00 00 00 0f 05 c3 e9 [0-32] 56 48 8b f4 48 83 e4 f0 48 83 ec 20 e8 ?? ?? ?? ?? 48 8b e6 5e c3}  //weight: 1, accuracy: Low
        $x_1_2 = {b9 fe 60 39 5b e8}  //weight: 1, accuracy: High
        $x_1_3 = {b9 3e 80 3c 9a e8}  //weight: 1, accuracy: High
        $x_1_4 = {e8 00 00 00 00 58 48 83 e8 05 48 2d ?? ?? ?? 00 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_MagniSyscall_A_2147848624_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/MagniSyscall.A"
        threat_id = "2147848624"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "MagniSyscall"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 8b d1 b8 [0-8] 66 c7 ?? ?? 0f 05 c6 ?? ?? c3 48 c7 ?? ?? 0b 00 00 00 c7 [0-4] 10 00 00 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {b9 b5 6f 4d 32 e8 ?? ?? ?? ?? 48 8b 4d ?? 33 d2 ff d0}  //weight: 1, accuracy: Low
        $x_1_3 = {b9 3e 80 3c 9a e8}  //weight: 1, accuracy: High
        $x_1_4 = {e8 00 00 00 00 58 48 83 e8 05 48 2d ?? ?? ?? 00 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

