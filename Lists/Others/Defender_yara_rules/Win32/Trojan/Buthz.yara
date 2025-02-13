rule Trojan_Win32_Buthz_A_2147734131_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Buthz.A"
        threat_id = "2147734131"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Buthz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {59 29 f6 01 c6 56 83 fb 00 74 37 6a ff 58 23 01 83 e9 fc 83 c0 cd c1 c8 08 29 f8 83 e8 01 31 ff 29 c7 f7 df c1 c7 09 d1 cf 6a 00 8f 06 01 06 8d 76 04 83 eb 04 [0-6] 05 87 d6 12 00 50 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

