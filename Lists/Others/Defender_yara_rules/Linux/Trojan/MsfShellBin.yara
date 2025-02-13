rule Trojan_Linux_MsfShellBin_A_2147794796_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/MsfShellBin.A"
        threat_id = "2147794796"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "MsfShellBin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 bb 2f 62 69 6e 2f 73 68 00 53 48 89 e7 52 57 48 89 e6 0f 05}  //weight: 1, accuracy: High
        $x_1_2 = {6a 3c 58 6a 01 5f 0f 05 5e 6a 26 5a 0f 05 48 85 c0 78 ed ff e6}  //weight: 1, accuracy: High
        $x_1_3 = {0f 05 48 96 6a 2b 58 0f 05 50 56 5f 6a 09 58 99 b6 10 48 89 d6 4d 31 c9 6a 22 41 5a b2 07 0f 05 48 96 48 97 5f 0f 05 ff e6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Linux_MsfShellBin_B_2147805397_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/MsfShellBin.B"
        threat_id = "2147805397"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "MsfShellBin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 6e 2f 73 68 68 2f 2f 62 69 89 e3 52 53 89 e1 b0 0b cd 80}  //weight: 1, accuracy: High
        $x_1_2 = {68 2f 2f 73 68 68 2f 62 69 6e 89 e3 50 53 89 e1 b0 0b cd 80}  //weight: 1, accuracy: High
        $x_1_3 = {6a 66 58 cd 80 d1 e3 b0 66 cd 80 57 43 b0 66 89 51 ?? cd 80 93 b6 0c b0 03 cd 80 87 df 5b b0 06 cd 80 ff e1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Linux_MsfShellBin_C_2147852975_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/MsfShellBin.C"
        threat_id = "2147852975"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "MsfShellBin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 89 e1 6a 09 5b 6a 66 58 cd 80 83 c4 10 59 5b}  //weight: 1, accuracy: High
        $x_1_2 = {6a 7d 58 99 b2 07 b9 00 10 00 00 89 e3 66 81 e3 00 f0 cd 80 31 db f7 e3 53 43 53 6a ?? 89 e1 b0 66 cd 80 51 6a 04 54 6a 02 6a 01 50 97 89 e1 6a 0e 5b 6a 66 58 cd 80}  //weight: 1, accuracy: Low
        $x_1_3 = {51 50 89 e1 6a 66 58 cd 80 d1 e3 b0 66 cd 80 57 43 b0 66 89 51 04 cd 80 93}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Linux_MsfShellBin_D_2147852976_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/MsfShellBin.D"
        threat_id = "2147852976"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "MsfShellBin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 db 53 89 e7 6a 10 54 57 53 89 e1 b3 07 ff 01 6a 66 58 cd 80 66 81 7f 02 ?? ?? 75 f1 5b 6a 02 59 b0 3f cd 80 49 79 f9 50 68 2f 2f 73 68 68 2f 62 69 6e 89 e3 50 53 89 e1}  //weight: 1, accuracy: Low
        $x_1_2 = {48 31 ff 48 31 db b3 18 48 29 dc 48 8d 14 24 48 c7 02 10 00 00 00 48 8d 74 24 08 6a 34 58 0f 05 48 ff c7 66 81 7e 02 ?? ?? 75 f0 48 ff cf 6a 02 5e 6a 21 58 0f 05 48 ff ce 79 f6 48 89 f3 bb 41 2f 73 68 b8 2f 62 69 6e 48 c1 eb 08 48 c1 e3 20 48 09 d8 50 48 89 e7 48 31 f6 48 89 f2 6a 3b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Linux_MsfShellBin_E_2147890087_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/MsfShellBin.E"
        threat_id = "2147890087"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "MsfShellBin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 db 53 43 53 6a 0a 89 e1 6a 66 58 cd 80 96 99 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 52 66 68 ?? ?? 66 68 0a 00 89 e1 6a 1c 51 56 89 e1 43 43 6a 66 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_MsfShellBin_F_2147890088_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/MsfShellBin.F"
        threat_id = "2147890088"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "MsfShellBin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {31 c9 31 db 53 53 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 53 66 68 ?? ?? 66 68 0a 00 89 e1 6a 1c 51 56 31 db 31 c0 b0 66 b3 03 89 e1 cd 80 31 db 39 d8 75 36 31 c9 f7 e1 89 f3 b0 3f cd 80 31 c0 41 89 f3 b0 3f cd 80 31 c0 41 89 f3 b0 3f cd 80}  //weight: 2, accuracy: Low
        $x_1_2 = {31 db 53 6a 0a f7 e3 89 e3 b0 a2 cd 80 e9 ?? ?? ?? ?? c3}  //weight: 1, accuracy: Low
        $x_1_3 = {31 db f7 e3 6a 06 6a 01 6a 0a 89 e1 b0 66 b3 01 cd 80 89 c6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Linux_MsfShellBin_G_2147891367_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/MsfShellBin.G"
        threat_id = "2147891367"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "MsfShellBin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 97 48 b9 ?? ?? ?? ?? ?? ?? ?? ?? 51 48 89 e6 6a 10 5a 6a 2a 58 0f 05 59 48 85 c0 79 ?? 49 ff c9 74 ?? 57 6a 23 58 6a ?? 6a ?? 48 89 e7 48 31 f6 0f 05 59 59 5f 48 85 c0 79 ?? 6a 3c 58 6a 01 5f 0f 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_MsfShellBin_H_2147891368_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/MsfShellBin.H"
        threat_id = "2147891368"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "MsfShellBin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 03 5e 6a 21 58 ff ce 0f 05 e0 ?? 6a 3b 58 99 48 bb 2f 62 69 6e 2f 73 68 00 53 54 5f 0f 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

