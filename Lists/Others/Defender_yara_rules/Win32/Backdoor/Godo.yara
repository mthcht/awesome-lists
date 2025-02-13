rule Backdoor_Win32_Godo_A_2147669150_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Godo.A"
        threat_id = "2147669150"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Godo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f 73 65 63 75 72 65 2f 75 70 64 61 74 65 (73 74 61 74|63 68 65) 2e 68 74 6d 6c 3f 69 64 3d 25 73 26}  //weight: 1, accuracy: Low
        $x_1_2 = "docs.google.com/viewer?url=%s&embedded=true" ascii //weight: 1
        $x_1_3 = "Answer for command [" ascii //weight: 1
        $x_1_4 = {c7 06 0d 00 00 00 e8 4a 73 ff ff 83 7c 24 10 06 0f 85 d8 00 00 00 83 7c 24 14 02 75 2a 38 9c 24 a6 00 00 00 0f 85 2b 01 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Godo_B_2147669168_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Godo.B"
        threat_id = "2147669168"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Godo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 79 6e 63 73 74 61 72 74 2e 68 74 6d 6c 3f 69 64 3d [0-15] 26 62 64 76 65 72 73 69 6f 6e 3d [0-6] 26 67 75 69 64 78 3d}  //weight: 1, accuracy: Low
        $x_1_2 = {6e 65 74 2e 65 78 65 20 6c 6f 63 61 6c 67 72 6f 75 70 20 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 73 00}  //weight: 1, accuracy: High
        $x_1_3 = {68 ff 00 00 00 56 57 ff 15 ?? ?? ?? ?? 85 c0 74 06 39 5c 24 ?? 75 0b ff 15 ?? ?? ?? ?? 83 f8 6d 74 6e 8b 4c 24 0c 88 1c 31 3b f3 75 12 8b 54 24 1c 56 83 c2 14 33 c0 52 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

