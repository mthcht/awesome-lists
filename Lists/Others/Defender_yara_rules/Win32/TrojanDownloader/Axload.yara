rule TrojanDownloader_Win32_Axload_A_2147608444_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Axload.A"
        threat_id = "2147608444"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Axload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "winifixer.com" ascii //weight: 5
        $x_2_2 = {49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 00 00 00 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 00 00 00 2f 6c 6f 67 33 2e 70 68 70 3f 74 6d 3d 25 64}  //weight: 2, accuracy: High
        $x_2_3 = {25 46 72 69 65 6e 64 6c 79 4e 61 6d 65 25 00 00 41 78 4c 6f 61 64 65 72 2e 4c 6f 61 64 65 72 2e 31}  //weight: 2, accuracy: High
        $x_2_4 = "{7D5DD829-6C90-42C5-B54C-2AFA82F988BA}" ascii //weight: 2
        $x_1_5 = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

