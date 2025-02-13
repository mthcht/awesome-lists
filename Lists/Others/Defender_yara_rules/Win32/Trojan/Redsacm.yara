rule Trojan_Win32_Redsacm_A_2147622608_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Redsacm.A"
        threat_id = "2147622608"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Redsacm"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 72 69 76 65 72 50 72 6f 63 [0-4] 5c 6d 73 61 63 6d 33 32 2e 64 72 76}  //weight: 1, accuracy: Low
        $x_1_2 = {40 3b c6 72 f4 07 00 80 b0 ?? ?? b8 72}  //weight: 1, accuracy: Low
        $x_1_3 = {eb 14 68 88 13 00 00 ff 15 ?? ?? ?? ?? eb 07}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

