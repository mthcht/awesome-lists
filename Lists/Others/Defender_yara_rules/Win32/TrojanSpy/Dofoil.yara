rule TrojanSpy_Win32_Dofoil_A_2147650460_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Dofoil.A"
        threat_id = "2147650460"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Dofoil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/sniffers.php" ascii //weight: 1
        $x_1_2 = {40 3f 0d 0a 53 65 72 76 65 72 3a 20 3f 20 28}  //weight: 1, accuracy: High
        $x_1_3 = {8b f8 8a 0f 80 f9 0d 74 12 80 f9 0a 74 0d 84 c9 74 09 8a 4f 01 47 80 f9 0d 75 ee}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

