rule Ransom_Win64_Booran_PA_2147935365_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Booran.PA!MTB"
        threat_id = "2147935365"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Booran"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HELLO_README.txt" ascii //weight: 1
        $x_1_2 = "!!! DANGER !!!" ascii //weight: 1
        $x_1_3 = "\\\\.\\pipe\\__rust_anonymous_pipe1__" ascii //weight: 1
        $x_1_4 = "Your files are encrypted, and currently unavailable." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Booran_A_2147935905_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Booran.A"
        threat_id = "2147935905"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Booran"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {42 49 47 20 66 69 6c 65 70 61 74 68 20 3d 20 3b 0a 20 20 20 20 20 20 20 20 66 69 6c 65 73 69 7a 65 20 3d 20 3b 0a 20 20 20 20 20 20 20 20 63 72 79 70 74 65 64 5f 73 69 7a 65 20 3d 20 3b 0a 20 20 20 20 20 20 20 20 63 6c 65 61 72 5f 73 69 7a 65 20 3d 20 3b}  //weight: 1, accuracy: High
        $x_1_2 = "Start dropping notes [*]" ascii //weight: 1
        $x_1_3 = {53 74 61 72 74 20 53 68 61 64 6f 77 20 43 6f ?? 79 20 64 65 6c 65 74 65 20 5b 2a 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Booran_PB_2147938064_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Booran.PB!MTB"
        threat_id = "2147938064"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Booran"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 89 e9 e8 ?? ?? ?? ?? 48 8b 8d ?? ?? ?? ?? 31 04 b9 48 ff c7 48 39 fe 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

