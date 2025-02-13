rule Trojan_Win64_Donipye_STH_2147781261_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Donipye.STH"
        threat_id = "2147781261"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Donipye"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 88 3c 08 48 ff c1 48 c1 ff 08 ff cb 4c 39 c9 0f 8d ?? ?? 00 00 84 db 75}  //weight: 1, accuracy: Low
        $x_1_2 = {48 b8 01 23 45 67 89 ab cd ef 48 89 ?? ?? ?? ?? ?? ?? 48 b8 fe dc ba 98 76 54 32 10 48 89}  //weight: 1, accuracy: Low
        $x_1_3 = {14 84 d7 17 48 ?? ?? ?? ?? 14 84 d7 17 e8}  //weight: 1, accuracy: Low
        $x_1_4 = "/CLRWrapper.go" ascii //weight: 1
        $x_1_5 = {43 63 32 6b 3d 0a f9 32 43 31 86 18 20 72 00 82 42 10 41 16 d8 f2 48 34 73 49}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win64_Donipye_STZ_2147781286_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Donipye.STZ"
        threat_id = "2147781286"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Donipye"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c2 48 8d 4c ?? ?? 48 03 c8 8d 42 ?? 30 01 ff c2 8b 44 ?? ?? 3b d0 72 e7}  //weight: 1, accuracy: Low
        $x_1_2 = {42 54 52 45 45 2e 64 6c 6c [0-16] 53 76 63 68 6f 73 74 50 75 73 68 53 65 72 76 69 63 65 47 6c 6f 62 61 6c 73}  //weight: 1, accuracy: Low
        $x_1_3 = {7d 7e 7c 7e c7 44 ?? ?? 78 6c 3e 7b 66 c7 44 ?? ?? 62 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

