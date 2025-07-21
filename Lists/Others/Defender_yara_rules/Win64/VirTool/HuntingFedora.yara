rule VirTool_Win64_HuntingFedora_C_2147947041_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/HuntingFedora.C"
        threat_id = "2147947041"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "HuntingFedora"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 89 ea 68 01 01 00 00 59 41 ba ?? ?? ?? ?? ff d5 50 50 4d 31 c9 4d 31 c0 48 ff c0 48 89 c2 48 ff c0 48 89 c1 41 ba}  //weight: 1, accuracy: Low
        $x_1_2 = {4c 89 e2 48 89 f9 41 ba ?? ?? ?? ?? ff d5 48 81 c4 40 02 00 00 49 b8 63 ?? ?? ?? ?? ?? ?? ?? 41 50 41 50 48 89 e2 57 57 57 4d 31 c0 6a 0d}  //weight: 1, accuracy: Low
        $x_1_3 = {4d 89 c1 4c 89 c1 41 ba ?? ?? ?? ?? ff d5 48 31 d2 48 ff ca 8b 0e 41 ba ?? ?? ?? ?? ff d5 bb f0 b5 a2 56 41 ba}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

