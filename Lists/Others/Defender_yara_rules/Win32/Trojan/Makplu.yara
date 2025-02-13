rule Trojan_Win32_Makplu_A_2147598165_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Makplu.A"
        threat_id = "2147598165"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Makplu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 f7 2b ca 51 56 8d 4c 24 ?? e8 ?? ?? ff ff 6a 01 68 ?? ?? ?? ?? 8d 4c 24 ?? e8 ?? ?? ff ff a1 ?? ?? ?? ?? 83 f8 ?? 77 ?? ff 24 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? eb ?? 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

