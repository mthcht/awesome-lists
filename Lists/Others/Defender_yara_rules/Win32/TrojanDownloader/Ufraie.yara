rule TrojanDownloader_Win32_Ufraie_A_2147598709_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Ufraie.A"
        threat_id = "2147598709"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Ufraie"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {76 09 30 04 08 40 3b 45 fc 72 f7 66 8b 01 66 3d 5a 4d 74 13 66 3d 4d 5a 74 0d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Ufraie_A_2147598709_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Ufraie.A"
        threat_id = "2147598709"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Ufraie"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {bb 0a 00 00 00 c7 45 f8 06 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {99 f7 f9 89 55 f0 83 fa 21}  //weight: 1, accuracy: High
        $x_1_3 = {be 0a 00 00 00 bf 06 00 00 00 c7 45 fc 08 00 00 00 c7 45 f8 0a 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {c7 45 e8 09 00 00 00 c7 45 e4 03 00 00 00 bb 03 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {bb 03 00 00 00 c7 45 e0 0a 00 00 00 c7 45 dc 08 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {b9 14 00 00 00 99 f7 f9}  //weight: 1, accuracy: High
        $x_1_7 = {bb 01 00 00 00 be 09 00 00 00 c7 45 cc 07 00 00 00 c7 45 c8 08 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_Win32_Ufraie_A_2147598709_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Ufraie.A"
        threat_id = "2147598709"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Ufraie"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\JWrok\\jrnAox\\gtEY.pdb" ascii //weight: 1
        $x_1_2 = "L:\\YgbYhovm\\awxZCcc\\lldbsf.pdb" ascii //weight: 1
        $x_1_3 = "T:\\yMeAlByr\\sqWdB\\Azdzf\\zpWD.pdb" ascii //weight: 1
        $x_1_4 = "Y:\\qdgcBbmy\\kjlWvaN\\OSxfbvt\\ynafl\\vifIrz.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_Win32_Ufraie_B_2147611593_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Ufraie.B"
        threat_id = "2147611593"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Ufraie"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {83 f8 04 75 19 81 7c 24 08 50 49 4e 47 75 0f 6a 00 6a 04}  //weight: 4, accuracy: High
        $x_5_2 = {6a 04 68 ff ff 00 00 56 e8 ?? ?? ?? 00 83 f8 ff 0f 84 ?? ?? 00 00 68 74 27 00 00 66 c7 44 24 14 02 00}  //weight: 5, accuracy: Low
        $x_4_3 = {3d 00 00 00 d0 77 07 3d 00 00 00 80 73 ?? ff d6 2b}  //weight: 4, accuracy: Low
        $x_5_4 = {32 d8 88 1c 08 8b 54 24 08 40 3b c2 72 ef 66 8b 01 66 3d 5a 4d 74 19 66 3d 4d 5a}  //weight: 5, accuracy: High
        $x_1_5 = "uniq=%d" ascii //weight: 1
        $x_1_6 = "fuck=%d" ascii //weight: 1
        $x_1_7 = "ras=%d" ascii //weight: 1
        $x_1_8 = "av=%s" ascii //weight: 1
        $x_1_9 = "winver=%d|%d|%d|%d|%d|%d|%s" ascii //weight: 1
        $x_1_10 = "kr_done" ascii //weight: 1
        $x_2_11 = "idt=%08x&vmdev=%d&avf=%d" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((2 of ($x_4_*))) or
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

