rule Trojan_Win32_Badkey_A_2147604826_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Badkey.A"
        threat_id = "2147604826"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Badkey"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 db 43 68 ?? ?? 00 00 e8 15 00 00 00 6a 00 6a 00 6a 00 53 e8 03 00 00 00 eb e7}  //weight: 1, accuracy: Low
        $x_1_2 = {6b 65 79 62 64 5f 65 76 65 6e 74 00 75 73 65 72 33 32 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_3 = {53 6c 65 65 70 00 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

