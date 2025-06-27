rule Trojan_Win32_Ghanarava_MCE_2147944916_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ghanarava.MCE!MTB"
        threat_id = "2147944916"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ghanarava"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {a8 69 42 00 ff f8 78 01 00 ff ff ff 08 00 00 00 01 00 00 00 06 00 00 00 e9 00 00 00 c8 67 42 00 5c 64 42 00 4c 7b 40 00 78}  //weight: 2, accuracy: High
        $x_1_2 = {4c 61 75 6e 63 68 65 72 20 66 6f 72 20 5a 61 70 72 65 74 00 4c 61}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

