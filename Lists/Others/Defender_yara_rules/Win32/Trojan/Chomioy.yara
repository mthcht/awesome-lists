rule Trojan_Win32_Chomioy_A_2147627393_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chomioy.A"
        threat_id = "2147627393"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chomioy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 db 6a 67 e8 ?? ?? ff ff 0f bf c0 50 e8 ?? ?? ff ff 66 85 c0 7d 0e 6a 11 e8 ?? ?? ff ff 66 85 c0 7d 02 b3 01 84 db 74 1f 80 3c 24 00 75 19 c6 04 24 01 6a 40}  //weight: 1, accuracy: Low
        $x_1_2 = "WinCE3.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

