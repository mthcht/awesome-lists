rule Ransom_Win64_FrndsEncryptor_A_2147913877_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FrndsEncryptor.A"
        threat_id = "2147913877"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FrndsEncryptor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 52 4e 44 53 3a 20 25 73 20 2f 70 61 74 68 2f 74 6f 2f 62 65 2f 65 6e 63 72 79 70 74 65 64 ?? 73 6c 69 63 65 20 62 6f 75 6e 64}  //weight: 1, accuracy: Low
        $x_1_2 = {4e 6f 72 6d 61 6c 20 46 69 6c 65 3a 20 25 73 ?? 45 52 52 4f 52 3a 20 25 64 20 21 3d 20 25 64}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

