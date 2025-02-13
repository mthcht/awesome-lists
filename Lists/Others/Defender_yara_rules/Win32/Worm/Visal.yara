rule Worm_Win32_Visal_A_2147636932_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Visal.A"
        threat_id = "2147636932"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Visal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Copy /b /y SendEmail.dll %SystemRoot%\\System32\\*.*" wide //weight: 1
        $x_1_2 = "Select * from Win32_Service where Name=" wide //weight: 1
        $x_1_3 = "Archive contacts" ascii //weight: 1
        $x_1_4 = "Waitting to send" ascii //weight: 1
        $x_1_5 = {5b 61 75 74 6f 72 75 6e 5d 0d 0a 6f 70 65 6e 3d 6f 70 65 6e 2e 65 78 65 0d 0a 69 63 6f 6e 3d 25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 73 79 73 74 65 6d 33 32 5c 53 48 45 4c 4c 33 32 2e 64 6c 6c 2c 34 0d 0a 61 63 74 69 6f 6e 3d 4f 70 65 6e 20 66 6f 6c 64 65 72 20 74 6f 20 76 69 65 77 20 66 69 6c 65 73 0d 0a 73 68 65 6c 6c 5c 6f 70 65 6e 3d 4f 70 65 6e 0d 0a 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 3d 6f 70 65 6e 2e 65 78 65 0d 0a 73 68 65 6c 6c 5c 6f 70 65 6e 5c 64 65 66 61 75 6c 74 3d 31}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

