rule TrojanDropper_Win32_Remplu_A_2147644452_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Remplu.A"
        threat_id = "2147644452"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Remplu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {70 6c 75 67 25 64 00 00 25 73 64 69 72 65 63 74 78 73 25 64 2e 64 61 74 00 00 00 00 70 6c 75 67 00 00 00 00 63 6f 75 6e 74 00 00 00 5b 70 6c 75 67 5d 0d 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

