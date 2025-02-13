rule Trojan_Win64_FrostLizzard_C_2147925362_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/FrostLizzard.C!dha"
        threat_id = "2147925362"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "FrostLizzard"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 44 24 40 33 d2 48 8b 44 24 40 8b 48 ?? e8 4e fd ff ff 48 89 84 24 ?? 00 00 00 48 ?? 44 24 40}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_FrostLizzard_F_2147928437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/FrostLizzard.F!dha"
        threat_id = "2147928437"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "FrostLizzard"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "powershell.exe -win 1 echo" wide //weight: 1
        $x_1_2 = {69 00 66 00 20 00 28 00 2d 00 6e 00 6f 00 74 00 28 00 54 00 65 00 73 00 74 00 2d 00 50 00 61 00 74 00 68 00 [0-80] 2d 00 50 00 61 00 74 00 68 00 54 00 79 00 70 00 65 00 20 00 4c 00 65 00 61 00 66 00}  //weight: 1, accuracy: Low
        $x_1_3 = "-ErrorVariable $e -uri" wide //weight: 1
        $x_1_4 = {45 00 78 00 70 00 61 00 6e 00 64 00 2d 00 41 00 72 00 63 00 68 00 69 00 76 00 65 00 20 00 2d 00 50 00 61 00 74 00 68 00 [0-32] 2d 00 44 00 65 00 73 00 74 00 69 00 6e 00 61 00 74 00 69 00 6f 00 6e 00 50 00 61 00 74 00 68 00 20 00 44 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 00 55 00 70 00 64 00 61 00 74 00 65 00}  //weight: 1, accuracy: Low
        $x_1_5 = ".docx -OutFile" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

