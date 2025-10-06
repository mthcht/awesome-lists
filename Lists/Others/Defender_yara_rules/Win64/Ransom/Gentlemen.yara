rule Ransom_Win64_Gentlemen_A_2147954278_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Gentlemen.A"
        threat_id = "2147954278"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Gentlemen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "README-GENTLEMEN.txt" ascii //weight: 1
        $x_1_2 = "--marker--" ascii //weight: 1
        $x_1_3 = {5b 57 25 21 64 28 4d 49 53 53 49 4e 47 29 5d 20 45 52 52 4f 52 20 25 21 73 28 4d 49 53 53 49 4e 47 29 20 3a 20 25 21 76 28 4d 49 53 53 49 4e 47 29 0a}  //weight: 1, accuracy: High
        $x_1_4 = "LOCKER_BACKGROUND=1" ascii //weight: 1
        $x_1_5 = {5b 2b 5d 20 d0 9d d0 b0 d1 87 d0 b0 d1 82 d0 be 20 d1 88 d0 b8 d1 84 d1 80 d0 be d0 b2 d0 b0 d0 bd d0 b8 d0 b5 2e 20 d0 a3 d1 85 d0 be d0 b4 d0 b8 d0 bc 20 d0 b2 20 d1 84 d0 be d0 bd 2e 2e 2e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

