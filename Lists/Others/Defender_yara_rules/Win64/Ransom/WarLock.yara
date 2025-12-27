rule Ransom_Win64_WarLock_A_2147947558_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/WarLock.A"
        threat_id = "2147947558"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "WarLock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {2e 00 78 00 32 00 61 00 6e 00 79 00 6c 00 6f 00 63 00 6b 00 00 00}  //weight: 3, accuracy: High
        $x_3_2 = {43 41 41 52 43 55 70 64 61 74 65 53 76 63 ?? ?? 73 00 71 00 6c 00 2e 00 65 00 78 00 65}  //weight: 3, accuracy: Low
        $x_1_3 = "Important!!!.pdf" wide //weight: 1
        $x_1_4 = "decryptiondescription.pdf" wide //weight: 1
        $x_1_5 = "How to decrypt my data.txt" wide //weight: 1
        $n_3_6 = "\\decrypt.pdb" ascii //weight: -3
        $n_3_7 = {4d 47 46 31 00 00 00 00 52 53 41 00 00 00 00 00 2d 2d 2d 2d 2d 42 45 47 49 4e 20 52 53 41 20 50 52 49 56 41 54 45 20 4b 45 59 2d 2d 2d 2d 2d}  //weight: -3, accuracy: High
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

