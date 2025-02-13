rule TrojanDropper_Win32_Smordess_A_2147719200_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Smordess.A"
        threat_id = "2147719200"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Smordess"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f a2 0f 31 4e 75 f9}  //weight: 1, accuracy: High
        $x_1_2 = {69 67 66 78 65 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

