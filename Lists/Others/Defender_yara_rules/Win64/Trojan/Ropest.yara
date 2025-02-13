rule Trojan_Win64_Ropest_B_2147689779_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Ropest.B"
        threat_id = "2147689779"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Ropest"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d e4 85 43 31 0f 84 ?? ?? ?? ?? 3d f7 dc ee b1 0f 84}  //weight: 1, accuracy: Low
        $x_1_2 = {74 17 48 63 40 3c b3 01 42 8b 4c 18 58 89 4d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

