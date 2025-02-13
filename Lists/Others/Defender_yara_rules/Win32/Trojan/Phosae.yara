rule Trojan_Win32_Phosae_B_2147724756_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Phosae.B!dha"
        threat_id = "2147724756"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Phosae"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "0x87a145f2, 0x9044, 0x4edd, 0xb9, 0x9f, 0xc0, 0xe9, 0x21, 0xa0, 0xf8, 0x51" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

