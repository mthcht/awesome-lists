rule Backdoor_Win64_RomComLoader_C_2147851923_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/RomComLoader.C"
        threat_id = "2147851923"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "RomComLoader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 8b c1 48 d3 e8 42 32 44 04 50 42 88 44 05 38 83 c1 08 41 03 d4 4d 03 c4 83 f9 40}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

