rule Ransom_Win64_Starlight_A_2147917227_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Starlight.A"
        threat_id = "2147917227"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Starlight"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "7cwMqm50Crkc3lDQWRLE5MYEiSvT3pil8dBBR7XXJKjVx3NMWVvPIcs=" ascii //weight: 1
        $x_1_2 = "fCny/pMgNAO7GxU8JYcardP/3PQoVSzZ0zPbDAxbevtaJAiC5oSZVK6OVbf0dbrCAqjWV9wSGO2" ascii //weight: 1
        $x_1_3 = "decrypt_key.nky" ascii //weight: 1
        $x_1_4 = "ransomware.rs" ascii //weight: 1
        $x_1_5 = "Encrypting large file" ascii //weight: 1
        $x_1_6 = "All the files in your computer has been encrypted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_Win64_Starlight_DA_2147917249_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Starlight.DA!MTB"
        threat_id = "2147917249"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Starlight"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "55"
        strings_accuracy = "Low"
    strings:
        $x_50_1 = "src/bin/ransomware.rs" ascii //weight: 50
        $x_50_2 = "src\\bin\\ransomware.rs" ascii //weight: 50
        $x_1_3 = {43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 20 00 50 00 61 00 6e 00 65 00 6c 00 5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 [0-15] 54 00 69 00 6c 00 65 00 57 00 61 00 6c 00 6c 00 70 00 61 00 70 00 65 00 72 00 [0-15] 57 00 61 00 6c 00 6c 00 70 00 61 00 70 00 65 00 72 00 53 00 74 00 79 00 6c 00 65 00}  //weight: 1, accuracy: Low
        $x_1_4 = {43 6f 6e 74 72 6f 6c 20 50 61 6e 65 6c 5c 44 65 73 6b 74 6f 70 [0-15] 54 69 6c 65 57 61 6c 6c 70 61 70 65 72 [0-15] 57 61 6c 6c 70 61 70 65 72 53 74 79 6c 65}  //weight: 1, accuracy: Low
        $x_1_5 = "chacha20poly" ascii //weight: 1
        $x_1_6 = "WakeByAddressAll" ascii //weight: 1
        $x_1_7 = "DeleteFileW" ascii //weight: 1
        $x_1_8 = "GetSystemTimeAsFileTime" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 5 of ($x_1_*))) or
            ((2 of ($x_50_*))) or
            (all of ($x*))
        )
}

