rule Worm_Win32_Allaple_M_2147605682_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Allaple.M"
        threat_id = "2147605682"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Allaple"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {55 8b ec 83 c4 e8 e8 00 00 00 00 5e 81 e6 00 00 ff ff 6a 30 59 64 8b 01 8b 40 0c 8b 40 1c 8b 00 8b 78 08 57 68 8e 4e 0e ec e8 52 02 00 00 89 45 f4 57 68 aa fc 0d 7c e8 44 02 00 00 89 45 f0 57 68 54 ca af 91 e8 36 02 00 00 89 45 ec 57 68 ac 33 06 03 e8 28 02 00 00 89 45 e8 6a 40 68 00 10 00 00 68 00 00 02 00 6a 00 ff 55 ec 89 45 fc 8b fe 03 76 3c 0f b7 4e 06 81 c6 f8 00 00 00 eb 10 8d 16 81 3a 2e 64 61 74 75 02 eb 08 83 c6 28 49 0b c9 75 ec 8b 46 0c 03 c7 ff 75 fc 50 e8 4e 02 00 00 8b 7d fc 03 7f 3c 6a 40 68 00 10 00 00 ff 77 50 6a 00 ff 55 ec 89 45 f8 ff 75 f8 ff 75 fc e8 ab 00 00 00 ff 75 f0 ff 75 f4 ff 75 f8 e8 0d 01 00 00 68 00 80 00 00 6a 00 ff 75 fc ff 55 e8 ff 75 f8 ff 75 f8 e8 0e 00 00 00 8b 45 f8 03 40 3c 8b 40 28 03 45 f8 ff e0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Allaple_A_2147663458_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Allaple.gen!A"
        threat_id = "2147663458"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Allaple"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<OBJECT type=\"application/x-oleobject\"CLASSID=\"CLSID:%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X\"></OBJECT>" ascii //weight: 1
        $x_1_2 = {5c 6c 73 61 72 70 63 00 5c 5c 2a 53 4d 42 53 45 52 56 45 52 5c 49 50 43 24 00 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 00 70 61 73 73 77 6f 72 64 5c 5c 25 73}  //weight: 1, accuracy: High
        $x_1_3 = {81 c4 ff ef ff ff 44 eb 02 eb 6b e8 f9 ff ff ff 53 55 56 57 8b 6c 24 18 8b 45 3c 8b 54 28 78 03 d5 8b 4a 18 8b 5a 20 03 dd e3 32 49 8b 34 8b 03 f5 33 ff fc 33 c0 ac 38 e0 74 07}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

