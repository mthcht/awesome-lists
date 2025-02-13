rule Trojan_Win64_TurtleLoader_CS_2147779765_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/TurtleLoader.CS!dha"
        threat_id = "2147779765"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "TurtleLoader"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 48 0f b7 4a 4a 4d 31 c9 48 31 c0 ac 3c 61 7c 02 2c 20 41 c1 c9 0d 41 01 c1 e2 ed 52 41 51 48 8b 52 20 8b 42 3c 48 01 d0 66 81 78 18 0b 02 75 72 8b 80 88 00 00 00 48 85 c0 74 67 48 01 d0 50 8b}  //weight: 1, accuracy: High
        $x_1_2 = {d0 e3 56 48 ff c9 41 8b 34 88 48 01 d6 4d 31 c9 48 31 c0 ac 41 c1 c9 0d 41 01 c1 38 e0 75 f1 4c 03 4c 24}  //weight: 1, accuracy: High
        $x_1_3 = {24 49 01 d0 66 41 8b 0c 48 44 8b 40 1c 49 01 d0 41 8b 04 88 48 01 d0 41 58 41 58 5e 59 5a 41 58 41 59 41 5a 48 83 ec 20 41 52 ff e0 58 41 59 5a 48 8b 12 e9 4f ff ff ff 5d 6a 00 49 be 77 69 6e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_TurtleLoader_NT_2147914402_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/TurtleLoader.NT!MTB"
        threat_id = "2147914402"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "TurtleLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {89 44 24 30 8b 44 24 3c c1 f8 02 89 44 24 3c 83 7c 24 3c 00 0f 8e ?? ?? ?? ?? 48 8b 44 24 40 0f b6 40 01 c1 e0 08 48 8b 4c 24 40 0f b6 09 01 c8 03 44 24 38}  //weight: 3, accuracy: Low
        $x_3_2 = {48 89 4c 24 40 48 8b 4c 24 40 e8 ?? ?? ?? ?? 89 44 24 3c 8b 44 24 3c}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

