rule Trojan_Win32_Ghoul_AQ_2147830405_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ghoul.AQ!MTB"
        threat_id = "2147830405"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ghoul"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {c7 05 9c f9 12 02 58 5d 06 02 c7 05 a0 f9 12 02 5c 5d 06 02 c7 05 a4 f9 12 02 60 5d 06 02 c7 05 ac f9 12 02 64 5d 06 02 c7 05 a8 f9 12 02 68 5d 06 02 c7 05 b4 f9 12 02 64 5d 06 02}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

