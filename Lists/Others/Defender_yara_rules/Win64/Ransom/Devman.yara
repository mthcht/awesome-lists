rule Ransom_Win64_Devman_C_2147956982_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Devman.C"
        threat_id = "2147956982"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Devman"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Path to the directory to encrypt (can be before or after flags)" ascii //weight: 1
        $x_1_2 = "Encrypting only provided path(s):" ascii //weight: 1
        $x_1_3 = "Error: failed to initialize crypto backend" ascii //weight: 1
        $x_1_4 = "Starting local encryption..." ascii //weight: 1
        $x_1_5 = "Failed to create README:" ascii //weight: 1
        $x_1_6 = "data_encryptor started with args:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

