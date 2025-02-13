rule Ransom_Win32_Kisucrypt_A_2147717158_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Kisucrypt.A"
        threat_id = "2147717158"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Kisucrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "103"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {2e 33 67 32 00 2e 33 67 70 00 2e 33 70 72}  //weight: 1, accuracy: High
        $x_1_3 = "secret.key" ascii //weight: 1
        $x_1_4 = "READTHISNOW!!!.txt" ascii //weight: 1
        $x_100_5 = {8a 06 46 32 45 f7 50 56 ff 45 f8 8b 75 f8 8a 06 46 8b 5d fc 39 5d f8 75 0c 8b 55 10 89 55 f8 8b 75 f8 8a 06 46 88 45 f7 5e 58 88 07 47 49 83 f9 00 75 cd}  //weight: 100, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Kisucrypt_A_2147717158_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Kisucrypt.A"
        threat_id = "2147717158"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Kisucrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8a 06 46 32 45 f7 50 56 ff 45 f8 8b 75 f8 8a 06 46}  //weight: 3, accuracy: High
        $x_3_2 = {83 c0 3c 8b 00 03 c2 83 c0 78 8b 00 03 c2 8b f8 83 c0 20 8b 00 03 c2 33 f6 50 8b 00 03 c2 bb ?? ?? ?? ?? 8a 08 8a 2b 84 c9}  //weight: 3, accuracy: Low
        $x_3_3 = {80 38 00 74 30 80 78 01 00 74 20 80 78 02 00 74 10 80 78 03 00 75 e6}  //weight: 3, accuracy: High
        $x_3_4 = {8d 57 10 c7 04 10 2a 2e 2a 00 ff 75 f4 8d 47 10 50}  //weight: 3, accuracy: High
        $x_3_5 = {80 7a 2c 2e 74 06 80 7a 2d 00 75 14 80 7a 2c 2e 0f 84 a3 00 00 00 80 7a 2c 2e}  //weight: 3, accuracy: High
        $x_3_6 = "Go to http://bitmessage.org/" ascii //weight: 3
        $x_1_7 = "tar,jar,bmp,swm,vault,xtbl,ctb,113,73b,a3d,abf" ascii //weight: 1
        $x_1_8 = "SUBJECT:" ascii //weight: 1
        $x_1_9 = "MESSAGE:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_3_*) and 2 of ($x_1_*))) or
            ((4 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Kisucrypt_A_2147717159_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Kisucrypt.A!!Kisucrypt.gen!A"
        threat_id = "2147717159"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Kisucrypt"
        severity = "Critical"
        info = "Kisucrypt: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8a 06 46 32 45 f7 50 56 ff 45 f8 8b 75 f8 8a 06 46}  //weight: 3, accuracy: High
        $x_3_2 = {83 c0 3c 8b 00 03 c2 83 c0 78 8b 00 03 c2 8b f8 83 c0 20 8b 00 03 c2 33 f6 50 8b 00 03 c2 bb ?? ?? ?? ?? 8a 08 8a 2b 84 c9}  //weight: 3, accuracy: Low
        $x_3_3 = {80 38 00 74 30 80 78 01 00 74 20 80 78 02 00 74 10 80 78 03 00 75 e6}  //weight: 3, accuracy: High
        $x_3_4 = {8d 57 10 c7 04 10 2a 2e 2a 00 ff 75 f4 8d 47 10 50}  //weight: 3, accuracy: High
        $x_3_5 = {80 7a 2c 2e 74 06 80 7a 2d 00 75 14 80 7a 2c 2e 0f 84 a3 00 00 00 80 7a 2c 2e}  //weight: 3, accuracy: High
        $x_3_6 = "Go to http://bitmessage.org/" ascii //weight: 3
        $x_1_7 = "tar,jar,bmp,swm,vault,xtbl,ctb,113,73b,a3d,abf" ascii //weight: 1
        $x_1_8 = "SUBJECT:" ascii //weight: 1
        $x_1_9 = "MESSAGE:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_3_*) and 2 of ($x_1_*))) or
            ((4 of ($x_3_*))) or
            (all of ($x*))
        )
}

