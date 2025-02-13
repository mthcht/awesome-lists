rule Trojan_Win32_Jibnuder_A_2147623084_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Jibnuder.gen!A"
        threat_id = "2147623084"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Jibnuder"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 14 06 02 14 24 32 d3 88 14 06 40 3d ?? ?? ?? ?? 75 ed}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 54 24 04 cd 2e c2 1c 00}  //weight: 1, accuracy: High
        $x_1_3 = {33 c0 8a 04 3e 8d 57 01 03 d2 33 c2 33 d2 8a d3 33 c2 88 04 3e 84 c0 75 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

