rule Trojan_Win32_Pmax_A_2147939493_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pmax.A!MTB"
        threat_id = "2147939493"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pmax"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 8c 24 b0 00 00 00 68 19 00 02 00 89 8c 24 34 02 00 00 c5 f8 28 8c 24 28 02 00 00 c5 f0 57 8c 24 18 01 00 00 6a 00 50 c5 f8 29 8c 24 20 01 00 00 68 01 00 00 80 c5 f8 77 ff d7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

