rule Trojan_Win32_Simpat_A_2147626165_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Simpat.A"
        threat_id = "2147626165"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Simpat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "esimp_dll.dll" wide //weight: 1
        $x_1_2 = "System32\\simp_dll.dll" wide //weight: 1
        $x_1_3 = {9c 60 89 76 04 83 6e 04 05 8b 46 04 2b 46 08 01 46 08 01 46 0c 01 46 10 01 46 14 01 46 18 01 46 1c 01 46 20 01 46 24 01 46 28 01 46 2c 01 46 30 01 46 34 01 46 40 8b 7e 0c 8b 46 48}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

