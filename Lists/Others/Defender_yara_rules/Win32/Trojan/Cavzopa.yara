rule Trojan_Win32_Cavzopa_A_2147621050_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cavzopa.A"
        threat_id = "2147621050"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cavzopa"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 c1 e0 04 8d 04 80 83 c0 64 50 6b c3 1e 83 c0 64 50 e8 ?? ?? ?? ?? 6a 0a e8 ?? ?? ?? ?? 43 83 fb 1a 75 db}  //weight: 1, accuracy: Low
        $x_1_2 = {ba 58 02 00 00 b8 20 03 00 00 e8 ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 43 0c 50 33 c0 8a 43 04 0f be 53 06 8d 14 52 8d 14 d5 ?? ?? ?? ?? 8b 04 82 50 e8 ?? ?? ?? ?? 8b 43 08 50 e8 ?? ?? ?? ?? 83 7d fc 00 75 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

