rule Trojan_Win64_SquidLoader_A_2147955255_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SquidLoader.A"
        threat_id = "2147955255"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SquidLoader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "[-]VirtualProtect failed:" ascii //weight: 1
        $x_1_2 = "[-]VirtualAlloc failed:" ascii //weight: 1
        $x_1_3 = "[-]CreateFiber failed:" ascii //weight: 1
        $x_1_4 = {30 0c 06 0f ?? ?? ?? ?? 30 4c 06 01 0f ?? ?? ?? ?? 30 4c 06 02 0f}  //weight: 1, accuracy: Low
        $x_1_5 = {30 ca 41 88 17 ?? ?? ?? ?? ?? ?? 00 41 0f b6 4f 01 0f ?? ?? ?? ?? ?? ?? 00 30 ca 41 88 57 01}  //weight: 1, accuracy: Low
        $x_1_6 = {48 b8 31 64 32 33 65 38 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {ba 50 14 0b 00 41 b9 42 4f 08 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win64_SquidLoader_PS_2147977624_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SquidLoader.PS!MTB"
        threat_id = "2147977624"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SquidLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {4e 8d 24 3f 4d 87 ea 45 8a 34 24 41 5b 4d 89 dd 41 55 41 80 f6 31 49 c7 c2 a1 00 00 00 41 80 c6 31 45 0f 5c c6 45 88 34 24 48 c1 e8 36 49 ff c7 49 09 c2 49 39 df 49 93 75}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

