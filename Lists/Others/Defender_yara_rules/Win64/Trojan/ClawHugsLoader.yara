rule Trojan_Win64_ClawHugsLoader_A_2147958266_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ClawHugsLoader.A!dha"
        threat_id = "2147958266"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ClawHugsLoader"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 74 5f 6c 6f 61 64 65 72 2e 64 6c 6c ?? 53 65 72 76 69 63 65 4d 61 69 6e ?? 53 74 61 72 74 45 6e 74 72 79 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ClawHugsLoader_C_2147959428_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ClawHugsLoader.C!dha"
        threat_id = "2147959428"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ClawHugsLoader"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 74 5f 6c 6f 61 64 65 72 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 62 5f 6c 6f 61 64 65 72 5f 6c 6f 63 61 6c 5f 64 6c 6c 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 62 5f 6c 6f 61 64 65 72 5f 6c 6f 63 61 6c 5f 62 69 6e 64 65 72 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 52 75 6e 64 6c 6c 33 32 45 6e 74 72 79 00 53 65 72 76 69 63 65 4d 61 69 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

