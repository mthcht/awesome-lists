rule Worm_Win32_Methoaf_B_2147641130_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Methoaf.B"
        threat_id = "2147641130"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Methoaf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 5f 52 ff d6 8d 85 ?? ?? ff ff 6a 6c 50 ff d6 8d 8d ?? ?? ff ff 6a 6f 51 ff d6 8d 95 ?? ?? ff ff 6a 76 52 ff d6 8d 85 ?? ?? ff ff 6a 65}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 5b 8d 4d bc 51 ff 15 ?? ?? ?? ?? 6a 61 8d 55 ac 52 ff 15 ?? ?? ?? ?? 6a 75 8d 45 8c 50 ff 15 ?? ?? ?? ?? 6a 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

