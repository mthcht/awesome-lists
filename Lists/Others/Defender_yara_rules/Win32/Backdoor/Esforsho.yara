rule Backdoor_Win32_Esforsho_A_2147684532_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Esforsho.A"
        threat_id = "2147684532"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Esforsho"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6c 6f 61 64 20 66 75 6e 20 2d 31 00}  //weight: 1, accuracy: High
        $x_1_2 = {45 78 65 63 75 74 65 20 2d 31 0d 0a}  //weight: 1, accuracy: High
        $x_1_3 = {68 e8 03 00 00 ff d3 a1 ?? ?? ?? ?? 85 c0 76 10 69 c0 60 ea 00 00 50 ff d3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

