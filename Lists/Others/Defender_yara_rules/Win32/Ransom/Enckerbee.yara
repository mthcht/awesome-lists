rule Ransom_Win32_Enckerbee_2147716805_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Enckerbee"
        threat_id = "2147716805"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Enckerbee"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "!!!! ATTENTION !!!!  YOUR FILES HAVE BEEN ENCRYPTED! !!!!" ascii //weight: 10
        $x_10_2 = "\\R980\\Release\\R980.pdb" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Enckerbee_A_2147716947_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Enckerbee.A!!Enckerbee.gen!A"
        threat_id = "2147716947"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Enckerbee"
        severity = "Critical"
        info = "Enckerbee: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "!!!! ATTENTION !!!!  YOUR FILES HAVE BEEN ENCRYPTED! !!!!" ascii //weight: 1
        $x_1_2 = "\\R980\\Release\\R980.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Enckerbee_B_2147717518_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Enckerbee.B"
        threat_id = "2147717518"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Enckerbee"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your email address %s@mailinator.com  Wait up to 24 hours for validation your TX" ascii //weight: 1
        $x_3_2 = {68 65 6c 70 5f 64 63 66 69 6c 65 2e 74 78 74 00 72 00 00 00 43 00 52 00 59 00 50 00 54 00 00 00 41 00 54 00 54 00 45 00 4e 00 54 00 49 00 4f 00}  //weight: 3, accuracy: High
        $x_1_3 = "taka\\documents\\cryptopp563\\simple.h" wide //weight: 1
        $x_2_4 = "1HfaCTfwsVXDitg9SgV8cR8ujYs7ZcKkt" ascii //weight: 2
        $x_3_5 = {6d 61 69 6c 69 6e 61 74 6f 72 2e 63 6f 6d 2f 69 6e 62 6f 78 32 2e 6a 73 70 3f 70 75 62 6c 69 63 5f 74 6f 3d 25 73 20 0a 0a 09 50 6c 65 61 73 65 20 77 61 69 74 20 75 70 20 74 6f 20 32 34 20 68 6f 75 72 73 20 66 6f 72 20 79 6f 75 72 20 64 65 63 72 79 70 74 20 6b 65 79 20 74 6f 20 61 72 72}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Enckerbee_B_2147717518_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Enckerbee.B"
        threat_id = "2147717518"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Enckerbee"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {68 65 6c 70 5f 64 63 66 69 6c 65 2e 74 78 74 00}  //weight: 2, accuracy: High
        $x_2_2 = {2f 63 20 73 63 68 74 61 73 6b 73 20 2f 63 72 65 61 74 65 20 2f 74 6e 20 65 6e 63 20 2f 74 72 20 22 43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 90 02 10 2e 65 78 65 22 20 2f 73 63 20 6f 6e 6c 6f 67 6f 6e 20 2f 72 6c 20 68 69 67 68 65 73 74 20 2f 66}  //weight: 2, accuracy: High
        $x_1_3 = "/rd hyghnhy /ig wfnwvra /e" ascii //weight: 1
        $x_1_4 = "/d rdwalrxr /divlav /ay vyd /ai" ascii //weight: 1
        $x_1_5 = "ADDRESS:  1HfaCTfwsVXDitg9SgV8cR8ujYs7ZcKkto" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Enckerbee_B_2147717519_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Enckerbee.B!!Enckerbee.gen!A"
        threat_id = "2147717519"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Enckerbee"
        severity = "Critical"
        info = "Enckerbee: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your email address %s@mailinator.com  Wait up to 24 hours for validation your TX" ascii //weight: 1
        $x_2_2 = {68 65 6c 70 5f 64 63 66 69 6c 65 2e 74 78 74 00 72 00 00 00 43 00 52 00 59 00 50 00 54 00 00 00 41 00 54 00 54 00 45 00 4e 00 54 00 49 00 4f 00}  //weight: 2, accuracy: High
        $x_1_3 = "taka\\documents\\cryptopp563\\simple.h" wide //weight: 1
        $x_1_4 = "1HfaCTfwsVXDitg9SgV8cR8ujYs7ZcKkt" ascii //weight: 1
        $x_2_5 = {6d 61 69 6c 69 6e 61 74 6f 72 2e 63 6f 6d 2f 69 6e 62 6f 78 32 2e 6a 73 70 3f 70 75 62 6c 69 63 5f 74 6f 3d 25 73 20 0a 0a 09 50 6c 65 61 73 65 20 77 61 69 74 20 75 70 20 74 6f 20 32 34 20 68 6f 75 72 73 20 66 6f 72 20 79 6f 75 72 20 64 65 63 72 79 70 74 20 6b 65 79 20 74 6f 20 61 72 72}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

