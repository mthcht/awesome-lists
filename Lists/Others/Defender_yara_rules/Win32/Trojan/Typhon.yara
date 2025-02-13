rule Trojan_Win32_Typhon_MBHI_2147851795_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Typhon.MBHI!MTB"
        threat_id = "2147851795"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Typhon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 84 24 a0 02 00 00 03 c1 66 ?? ?? ?? a2 02 00 00 41 83 f9 33 72}  //weight: 1, accuracy: Low
        $x_1_2 = {6c 74 78 71 6b 63 62 77 77 73 6a 62 6f 6e 70 00 72 76 78 67 64 79 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

