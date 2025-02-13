rule Virus_Win32_Chir_2147717323_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Chir.gen!dam"
        threat_id = "2147717323"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Chir"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "dam: damaged malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3d 2e 77 61 62 74 21 3d 2e 61 64 63 74 25 3d 72 2e 64 62 74 1e 3d 2e 64 6f 63 74 17 3d 2e 78 6c 73 74 10}  //weight: 1, accuracy: High
        $x_1_2 = {83 c0 20 3b f8 77 e2 80 f9 40 74 45 80 f9 2e 74 3c 80 f9 30 72 0f 80 f9 39 72 38 80 f9 41 72 05 80 f9 7e 72 2e}  //weight: 1, accuracy: High
        $x_1_3 = {3d 2e 65 78 65 74 53 3d 2e 73 63 72 74 4c 3d 2e 68 74 6d 74 0b 3d 68 74 6d 6c 74 04}  //weight: 1, accuracy: High
        $x_1_4 = {ff 96 80 00 00 00 58 03 c7 c7 00 2e 65 6d 6c c7 40 04 00 00 00 00 6a 00 57 ff 56 70 83 f8 ff}  //weight: 1, accuracy: High
        $x_1_5 = "<html><HEAD></HEAD><body bgColor=3D#ffffff><iframe src=3Dcid:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

