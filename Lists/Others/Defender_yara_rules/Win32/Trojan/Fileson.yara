rule Trojan_Win32_Fileson_A_2147654123_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fileson.A"
        threat_id = "2147654123"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fileson"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {65 73 6f 6e 69 63 2e 63 6f 6d 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 47 45 54 20 2f 6c 69 6e 6b 3f 6d 65 74 68 6f 64 3d 67 65 74 44 6f 77 6e 6c 6f 61 64 4c 69 6e 6b 26 66 6f 72 6d 61 74 3d 78 6d 6c 26 75 3d}  //weight: 1, accuracy: Low
        $x_1_2 = "&password=" ascii //weight: 1
        $x_1_3 = "uzzy." ascii //weight: 1
        $x_1_4 = {66 73 6e 31 2e 64 6c 6c 00 4c 33 32}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

