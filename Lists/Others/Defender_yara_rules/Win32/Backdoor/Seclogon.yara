rule Backdoor_Win32_Seclogon_A_2147629029_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Seclogon.A!dll"
        threat_id = "2147629029"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Seclogon"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 53 79 73 74 65 6d 33 32 5c 73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b 20 77 69 6e 73 65 63 6c 6f 67 6f 6e 00}  //weight: 1, accuracy: High
        $x_1_2 = {73 63 20 63 6f 6e 66 69 67 20 55 49 30 44 65 74 65 63 74 20 73 74 61 72 74 3d 20 64 69 73 61 62 6c 65 64 00}  //weight: 1, accuracy: High
        $x_1_3 = {c7 43 04 02 00 00 00 c7 43 08 20 00 00 00 c7 43 0c ff 01 0f 00 c7 43 10 01 00 00 00 8d 43 14 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d 43 18 ba ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

