rule Backdoor_Win32_Datcaen_A_2147661735_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Datcaen.A"
        threat_id = "2147661735"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Datcaen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 6d 73 6f 65 72 74 32 2e 62 61 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {68 f4 01 00 00 ff 15 ?? ?? ?? ?? be 04 28 00 00 56 8d 45 ?? 53 50 e8 ?? ?? ?? ?? 83 c4 0c 53 53 53 53 53 ff 55}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

