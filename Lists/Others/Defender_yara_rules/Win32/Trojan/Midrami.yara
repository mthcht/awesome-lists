rule Trojan_Win32_Midrami_A_2147741069_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Midrami.A"
        threat_id = "2147741069"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Midrami"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6e 65 6c 33 c7 05 ?? ?? ?? 00 32 2e 64 6c 66 c7 05 ?? ?? ?? 00 65 72 66 c7 05 ?? ?? ?? 00 6c 00 c6 05}  //weight: 1, accuracy: Low
        $x_1_2 = {00 6c 65 33 32 c7 05 ?? ?? ?? 00 4d 6f 64 75 c7 05 ?? ?? ?? 00 72 73 74 57 66 c7 05 ?? ?? ?? 00 46 69}  //weight: 1, accuracy: Low
        $x_1_3 = {72 74 75 61 c7 05 ?? ?? ?? ?? 74 65 63 74 c7 05 ?? ?? ?? ?? 6c 50 72 6f 66 c7 05 ?? ?? ?? ?? 56 69}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

