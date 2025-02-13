rule Trojan_Win32_Junkoil_A_2147599279_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Junkoil.A"
        threat_id = "2147599279"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Junkoil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {85 c0 74 31 68 ?? ?? 40 00 6a 00 68 01 00 1f 00 e8 ?? ?? ff ff 85 c0 75 ?? 68 ?? ?? 40 00 6a 00 68 66 66 66 66 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

