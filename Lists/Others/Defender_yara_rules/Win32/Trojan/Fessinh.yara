rule Trojan_Win32_Fessinh_2147597221_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fessinh"
        threat_id = "2147597221"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fessinh"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 85 00 ff ff ff 50 e8 ?? ?? f7 ff 85 c0 75 07 c6 85 00 ff ff ff 43 8a 85 00 ff ff ff 50 e8 ?? ?? f7 ff 83 f8 01 1b c0 40 84 c0 75 07 c6 85 00 ff ff ff 43 8d 85 fc fe ff ff 8a 95 00 ff ff ff e8 ?? ?? f7 ff 8b 95 fc fe ff ff 8b c3 b9 ?? ?? ?? 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

