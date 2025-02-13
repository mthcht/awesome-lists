rule Trojan_Win32_Patch_E_2147642580_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Patch.E"
        threat_id = "2147642580"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Patch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 3a 5c 44 6f 63 75 6d 65 6e 74 73 20 61 6e 64 20 53 65 74 74 69 6e 67 73 5c 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 5c 4c 6f 63 61 6c 20 53 65 74 74 69 6e 67 73 5c 41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 5c 6d 73 76 63 72 2e 64 6c 6c 1d 00 90 90 90 b8 ?? ?? ?? ?? 90 90 90 50 90 90 90 ff 15 ?? ?? ?? ?? 90 90 90 e9 4e e0 ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

