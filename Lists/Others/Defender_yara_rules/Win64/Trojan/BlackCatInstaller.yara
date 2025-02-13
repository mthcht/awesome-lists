rule Trojan_Win64_BlackCatInstaller_A_2147903962_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BlackCatInstaller.A"
        threat_id = "2147903962"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BlackCatInstaller"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 65 76 69 63 65 49 6f 43 6f 6e 74 72 6f 6c 00 46 69 6e 64 46 69 72 73 74 46 69 6c 65 41 00 43 72 65 61 74 65 46 69 6c 65 57 00 33 36 33 2e 73 79 73 00 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 00 6e 74 64 6c 6c 2e 64 6c 6c 00 6b 65 72 6e 65 6c 62 61 73 65 2e 64 6c 6c 00 00 42 00 49 00 4e 00 41 00 52 00 59 00}  //weight: 1, accuracy: High
        $x_1_2 = {64 00 6c 00 6c 00 2c 00 44 00 6c 00 6c 00 4d 00 61 00 69 00 6e 00 00 00 43 00 3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 00 00 43 3a 5c 77 69 6e 64 6f 77 73 5c 74 61 73 6b 73 5c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

