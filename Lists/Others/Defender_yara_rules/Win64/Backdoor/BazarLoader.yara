rule Backdoor_Win64_BazarLoader_STB_2147767124_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/BazarLoader.STB"
        threat_id = "2147767124"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6c 64 31 2e 64 6c 6c 00 53 74 61 72 74 46 75 6e 63 00}  //weight: 1, accuracy: High
        $x_1_2 = {77 73 32 5f 33 32 64 6c 6c 00 6e 74 64 6c 6c 2e 64 6c 6c 00 73 68 65 6c 6c 33 32 2e 64 6c 6c 00 77 69 6e 69 6e 65 74 2e 64 6c 6c 00 75 72 6c 6d 6f 6e 2e 64 6c 6c}  //weight: 1, accuracy: High
        $x_1_3 = {48 8b 00 48 b9 00 00 00 00 ff ff ff ff 48 8b 40 30 48 23 c1 48 89 ?? ?? ?? 48 8b ?? ?? ?? 8b 40 08 48 0b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

