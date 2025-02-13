rule Ransom_Win32_Orxlocker_A_2147705978_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Orxlocker.A"
        threat_id = "2147705978"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Orxlocker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 00 50 00 61 00 79 00 6d 00 65 00 6e 00 74 00 2d 00 49 00 6e 00 73 00 74 00 72 00 75 00 63 00 74 00 69 00 6f 00 6e 00 73 00 2e 00 68 00 74 00 6d 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = ".onion/get.php" wide //weight: 1
        $x_1_3 = {2e 00 4c 00 4f 00 43 00 4b 00 45 00 44 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "File Recovery Required" wide //weight: 1
        $x_1_5 = {65 6e 74 65 72 20 79 6f 75 72 20 50 61 79 6d 65 6e 74 20 49 44 20 66 72 6f 6d 20 61 62 6f 76 65 2e 3c 62 72 3e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

