rule Trojan_Win64_AppleCider_A_2147959131_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AppleCider.A!dha"
        threat_id = "2147959131"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AppleCider"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "d94Dfbjhse@#bN82" ascii //weight: 1
        $x_1_2 = "h49sDTby4#@bf#bv@" ascii //weight: 1
        $x_1_3 = "@hdtT7Sbfh@#FHGs" ascii //weight: 1
        $x_1_4 = {00 73 63 69 74 65 72 2e 6d 75 69 00}  //weight: 1, accuracy: High
        $x_1_5 = {43 00 3a 00 c7 45 ?? 5c 00 57 00 c7 45 ?? 69 00 6e 00 c7 45 ?? 64 00 6f 00 c7 45 ?? 77 00 73 00 c7 45 ?? 5c 00 53 00 c7 45 ?? 79 00 73 00 c7 45 ?? 74 00 65 00 c7 45 ?? 6d 00 33 00 c7 45 ?? 32 00 5c 00 c7 45 ?? 6d 00 63 00 c7 45 ?? 62 00 75 00 c7 45 ?? 69 00 6c 00 c7 45 ?? 64 00 65 00 c7 45 ?? 72 00 2e 00 c7 45 ?? 65 00 78 00 c7 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

