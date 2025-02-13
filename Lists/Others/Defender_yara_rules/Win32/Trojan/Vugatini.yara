rule Trojan_Win32_Vugatini_A_2147834745_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vugatini.A!dha"
        threat_id = "2147834745"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vugatini"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 4a 02 c1 e9 08 88 4a 01 c1 e9 08 88 0a 83 c2 03 33 c9 8d 71 04}  //weight: 1, accuracy: High
        $x_1_2 = {c1 e9 02 88 4a 01 c1 e9 08 83 c0 02 88 0a 8b 4d fc}  //weight: 1, accuracy: High
        $x_1_3 = "C:\\Windows\\VGAuthCLI.bin" ascii //weight: 1
        $x_1_4 = {56 47 41 75 74 68 2e 64 6c 6c 00 76 6d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

