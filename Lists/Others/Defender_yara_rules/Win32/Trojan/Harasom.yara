rule Trojan_Win32_Harasom_A_2147680393_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Harasom.A"
        threat_id = "2147680393"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Harasom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 53 89 06 58 6a 4f 66 89 45 ?? 58 6a 46 66 89 45 ?? 58 6a 54 66 89 45 ?? 58 6a 57 66 89 45}  //weight: 1, accuracy: Low
        $x_1_2 = {56 33 f6 68 ?? ?? ?? ?? 46 e8 ?? ?? ?? ?? 59 6a 40 68 00 30 00 00 ff 75 0c 6a 00 ff 75 08 ff d0 5e 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

