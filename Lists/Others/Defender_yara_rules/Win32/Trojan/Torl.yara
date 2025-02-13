rule Trojan_Win32_Torl_A_2147630220_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Torl.A"
        threat_id = "2147630220"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Torl"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 93 80 03 00 00 0f b6 92 6a 02 00 00 4a 80 ea 01 0f 92 c1 ba ?? ?? ?? ?? e8 ?? ?? ff ff 8b 83 84 03 00 00 8b 80 70 02 00 00 8b 10 ff 52 14}  //weight: 1, accuracy: Low
        $x_1_2 = "\\userprofile.dll\",work" wide //weight: 1
        $x_1_3 = "\\firefox\\profiles.ini" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

