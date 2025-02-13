rule TrojanDropper_Win32_Kilim_B_2147693598_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Kilim.B"
        threat_id = "2147693598"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Kilim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {62 61 63 6b 67 72 6f 75 6e 64 2e 6a 73 9d 52 c1 6a 1b 31 10 bd 07 f2 0f 83 4e 6b 30 eb 1e 7a 4a eb 5e 4a 68 03 29 2d 71 02 05 93 83 2c 8d bd a2 bb 92}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

