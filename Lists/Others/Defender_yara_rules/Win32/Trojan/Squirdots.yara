rule Trojan_Win32_Squirdots_A_2147621445_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Squirdots.A"
        threat_id = "2147621445"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Squirdots"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/c taskkill /f /im expl" wide //weight: 1
        $x_1_2 = {2f 00 63 00 20 00 72 00 64 00 20 00 63 00 3a 00 5c 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 5c 00 20 00 2f 00 73 00 2f 00 71 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "/c del /f /s /q C:\\*." wide //weight: 1
        $x_1_4 = {73 00 68 00 75 00 74 00 64 00 6f 00 77 00 6e 00 00 [0-8] 2d 00 74 00 20 00 31 00 20 00 2d 00 66 00 20 00 2d 00 72 00 20 00 2d 00 63 00}  //weight: 1, accuracy: Low
        $x_1_5 = {72 00 65 00 67 00 73 00 76 00 72 00 33 00 32 00 20 00 55 00 52 00 4c 00 4d 00 4f 00 4e 00 2e 00 64 00 6c 00 6c 00 20 00 2f 00 75 00 20 00 2f 00 73 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

