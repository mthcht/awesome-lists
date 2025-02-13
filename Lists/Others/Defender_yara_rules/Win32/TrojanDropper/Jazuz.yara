rule TrojanDropper_Win32_Jazuz_A_2147639900_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Jazuz.A"
        threat_id = "2147639900"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Jazuz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 74 65 6d 70 2e 74 6d 70 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 72 75 6e 2e 6a 61 72 00}  //weight: 1, accuracy: High
        $x_1_3 = {2d 6a 61 72 20 22 25 73 22 20 22 25 73 22 00}  //weight: 1, accuracy: High
        $x_1_4 = {6a 00 68 80 00 00 00 6a 02 6a 00 6a 02 68 00 00 00 40 [0-10] ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

