rule Trojan_Win32_RazXor_2147816562_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RazXor!MTB"
        threat_id = "2147816562"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RazXor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 34 30 01 d2 8b 36 81 ea ?? ?? ?? ?? 81 e6 ff 00 00 00 09 ca 40 49 01 c9 81 f8 f4 01 00 00 75 [0-1] b8 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {81 c1 01 00 00 00 31 33 81 c3 01 00 00 00 39 fb 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

