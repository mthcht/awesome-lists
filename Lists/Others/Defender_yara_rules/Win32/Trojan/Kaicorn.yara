rule Trojan_Win32_Kaicorn_A_2147733552_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kaicorn.A!bit"
        threat_id = "2147733552"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kaicorn"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 b8 04 00 02 80 c7 45 b0 0a 00 00 00 8d 45 b0 50 e8}  //weight: 1, accuracy: High
        $x_1_2 = {00 4b 61 77 61 69 69 2d 55 6e 69 63 6f 72 6e 00 4b 61 77 61 69 69 2d 55 6e 69 63 6f 72 6e 00 00 56 62 31 00}  //weight: 1, accuracy: High
        $x_1_3 = {5c 00 55 00 6e 00 69 00 63 00 6f 00 72 00 6e 00 2d 00 [0-48] 63 00 6d 00 64 00 20 00 2f 00 63 00 20 00 72 00 ?? ?? 6e 00 61 00 6d 00 65 00 20 00 22 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

