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

