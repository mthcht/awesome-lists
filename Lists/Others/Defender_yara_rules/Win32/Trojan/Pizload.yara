rule Trojan_Win32_Pizload_B_2147610866_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pizload.B"
        threat_id = "2147610866"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pizload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\drivers\\huoxingjh.sys" ascii //weight: 1
        $x_1_2 = {75 6e 6b 6e 6f 77 6e 00 25 73 5c 64 72 69 76 65 72 73 5c 25 73}  //weight: 1, accuracy: High
        $x_1_3 = {83 f8 40 0f 94 c2 c1 e1 06 83 e0 3f 0b c1 8b c8 2b ea 47 83 ff 04 75 1d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

