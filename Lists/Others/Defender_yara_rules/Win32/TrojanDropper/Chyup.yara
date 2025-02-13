rule TrojanDropper_Win32_Chyup_A_2147629805_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Chyup.A"
        threat_id = "2147629805"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Chyup"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FPC 1.0.6 [2002/04/23] for i386 - WIN32" ascii //weight: 1
        $x_1_2 = {4b 2d 4d 65 6c 65 6f 6e 5c 00 0c 00 00 00 0c 00 00 00 ff ff ff ff 46 69 6e 65 42 72 6f 77 73 65 72 5c 00 09}  //weight: 1, accuracy: High
        $x_1_3 = {53 45 41 47 55 4c 4c 5c 46 54 50 5c 00 0d 00 00 00 0d 00 00 00 ff ff ff ff 41 63 6f 6f 20 42 72 6f 77 73 65 72 5c 00 07}  //weight: 1, accuracy: High
        $x_1_4 = {68 6e 65 74 63 66 67 2e 64 6c 6c 00 0c 00 00 00 0c 00 00 00 ff ff ff ff 72 61 73 61 64 68 6c 70 2e 64 6c 6c 00 0c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

