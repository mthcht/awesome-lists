rule Backdoor_Win64_Myrddin_B_2147796216_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Myrddin.B"
        threat_id = "2147796216"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Myrddin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "merlin" ascii //weight: 1
        $x_1_2 = {0f 10 00 0f 11 84 24 48 01 00 00 48 8b ?? ?? ?? ?? ?? 48 8b ?? ?? ?? ?? ?? 48 89 ?? ?? ?? ?? ?? ?? 48 89 ?? ?? ?? ?? ?? ?? 48 8b ?? ?? ?? ?? ?? 48 8b ?? ?? ?? ?? ?? 48 89 ?? ?? ?? ?? ?? ?? 48 89 ?? ?? ?? ?? ?? ?? 48 8b ?? ?? ?? ?? ?? 48 8b ?? ?? ?? ?? ?? 48 89 ?? ?? ?? ?? ?? ?? 48 89 ?? ?? ?? ?? ?? ?? 48 8b ?? ?? ?? ?? ?? 48 8b ?? ?? ?? ?? ?? 48 89 ?? ?? ?? ?? ?? ?? 48 89 ?? ?? ?? ?? ?? ?? 48 8b ?? ?? ?? ?? ?? 48 8b ?? ?? ?? ?? ?? 48 89 ?? ?? ?? ?? ?? ?? 48 89 ?? ?? ?? ?? ?? ?? 48 8b ?? ?? ?? ?? ?? 48 8b ?? ?? ?? ?? ?? 48 89 ?? ?? ?? ?? ?? ?? 48 89 ?? ?? ?? ?? ?? ?? 48 8b ?? ?? ?? ?? ?? 48 8b ?? ?? ?? ?? ?? 48 89 ?? ?? ?? ?? ?? ?? 48 89 ?? ?? ?? ?? ?? ?? 48 8b}  //weight: 1, accuracy: Low
        $x_1_3 = {01 00 00 48 8b 0d ?? ?? ?? ?? 48 8b ?? ?? ?? ?? ?? 48 8b ?? ?? ?? ?? ?? 48 89 ?? ?? ?? ?? ?? ?? 48 89 ?? ?? ?? ?? ?? ?? 48 89 ?? ?? ?? ?? ?? ?? 48 8b}  //weight: 1, accuracy: Low
        $x_1_4 = {48 85 c9 0f 85 ?? 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

