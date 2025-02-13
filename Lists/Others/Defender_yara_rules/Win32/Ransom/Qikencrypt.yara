rule Ransom_Win32_Qikencrypt_A_2147692941_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Qikencrypt.A"
        threat_id = "2147692941"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Qikencrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "*.odt,*.ods,*.odp,*.odb,*." ascii //weight: 1
        $x_1_2 = "*.tar,*.eml,*.1cd,*" ascii //weight: 1
        $x_1_3 = "/startenc.txt" ascii //weight: 1
        $x_1_4 = "lst.php?str=" ascii //weight: 1
        $x_1_5 = "/index.php?ids=" ascii //weight: 1
        $x_1_6 = "</key>" ascii //weight: 1
        $x_2_7 = "chickenkiller.com" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Qikencrypt_C_2147697657_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Qikencrypt.C"
        threat_id = "2147697657"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Qikencrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {65 6e 63 66 69 6c 65 73 2e 74 78 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {66 69 6c 65 73 2e 6c 69 73 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {65 6e 63 6d 73 67 2e 68 74 6d 6c 00}  //weight: 1, accuracy: High
        $x_1_4 = {77 69 6e 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_2_5 = {77 69 6e 73 74 61 72 74 2e 65 78 65 00}  //weight: 2, accuracy: High
        $x_2_6 = {4c 6f 73 74 45 76 69 6c 00}  //weight: 2, accuracy: High
        $x_2_7 = {3c 2f 45 6e 63 72 79 70 74 69 6f 6e 4b 65 79 3e 00}  //weight: 2, accuracy: High
        $x_2_8 = {2f 69 6e 64 65 78 2e 70 68 70 3f 61 63 74 3d 73 26 73 3d 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

