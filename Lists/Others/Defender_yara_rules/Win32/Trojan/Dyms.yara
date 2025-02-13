rule Trojan_Win32_Dyms_A_2147648164_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dyms.A"
        threat_id = "2147648164"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dyms"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2a 28 53 59 29 23 20 63 6d 64 00 00 2a 28 53 59 29 23 00 00 73 65 6e 64 20 3d 20 25 64 00 00 00 2a 28 53 59 29 23 20 00 63 6d 64 2e 65 78 65 00 65 78 69 74}  //weight: 1, accuracy: High
        $x_1_2 = {f2 ae f7 d1 49 51 8d 4c 24 ?? 68 ?? ?? ?? ?? 51 e8 ?? ?? ?? ?? 56 8d 54 24 ?? 68 ?? ?? ?? ?? 52 e8 ?? ?? ?? ?? 83 c4 18 83 fe ff 0f 84 ?? ?? ?? ?? b9 3f 00 00 00 33 c0 8d 7c 24 ?? ?? ?? f3 ab 66 ab aa 8d 44 24 ?? 68 ff 00 00 00 50 55 e8 ?? ?? ?? ?? 83 f8 ff 0f 84}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

