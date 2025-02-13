rule TrojanDropper_Win32_Astercax_A_2147599461_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Astercax.A"
        threat_id = "2147599461"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Astercax"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 e8 4f 0f 80 a6 04 00 00 50 8d 47 50 50 6a 28 ff 15 ?? ?? 40 00 6a 01 6a 01 ff 15 ?? ?? 40 00 83 e8 27 0f 80 86 04 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Astercax_B_2147624119_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Astercax.B"
        threat_id = "2147624119"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Astercax"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 e8 4f 0f 80 ec 05 00 00 50 8d 47 3c 50 6a 28 ff 15 ?? ?? 40 00 6a 01 6a 01 ff 15 ?? ?? 40 00 83 e8 27 0f 80 cc 05 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

