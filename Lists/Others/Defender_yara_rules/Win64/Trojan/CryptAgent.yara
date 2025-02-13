rule Trojan_Win64_CryptAgent_A_2147777320_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CryptAgent.A!dha"
        threat_id = "2147777320"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CryptAgent"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 38 47 75 36 80 78 01 65 75 30 80 78 02 74 75 2a 80 78 03 50 75 24 80 78 04 72 75 1e 80 78 05 6f 75 18 80 78 06 63 75 12 80 78 07 41 75 0c 80 78 08 64 75 06 80 78 09 64 74 1c}  //weight: 1, accuracy: High
        $x_1_2 = {ba 04 01 00 00 c7 45 40 5c 61 63 63 48 8d 8d b0 00 00 00 c7 45 44 65 73 73 2e c7 45 48 6c 6f 67 00 e8 be 28 00 00 33 f6 48 8d 8d b0 00 00 00 41 be 03 00 00 00 48 89 74 24 30 89 74 24 28 45 33 c9 45 8b c6 44 89 74 24 20 ba 00 00 00 80 ff 15 8c c8 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CryptAgent_B_2147777331_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CryptAgent.B!dha"
        threat_id = "2147777331"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CryptAgent"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 38 47 75 36 80 78 01 65 75 30 80 78 02 74 75 2a 80 78 03 50 75 24 80 78 04 72 75 1e 80 78 05 6f 75 18 80 78 06 63 75 12 80 78 07 41 75 0c 80 78 08 64 75 06 80 78 09 64 74 1c}  //weight: 1, accuracy: High
        $x_1_2 = {80 74 05 80 cc 48 ff c0 48 83 f8 42 7c f2}  //weight: 1, accuracy: High
        $x_1_3 = {80 74 04 50 aa 48 ff c0 48 83 f8 27 7c f2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

