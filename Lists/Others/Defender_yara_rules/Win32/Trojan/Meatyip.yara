rule Trojan_Win32_Meatyip_A_2147608417_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meatyip.A"
        threat_id = "2147608417"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meatyip"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 08 83 f9 30 7c 2d 83 f9 7d 7f 28 83 c1 12 0f 80 f1 00 00 00 83 f9 7d 7e 1a 83 e9 7d 0f 80 e3 00 00 00 83 c1 30 0f 80 da 00 00 00 2b cf 0f 80 d2 00 00 00 e8 ?? ?? ?? ff 8a d0 ff 75 dc ff 75 e0 88 55 8f e8 ?? ?? ?? ff 8a 4d 8f 88 08 6a 01}  //weight: 10, accuracy: Low
        $x_5_2 = "e3x8is6wni{2v3;7n" wide //weight: 5
        $x_1_3 = "member" wide //weight: 1
        $x_1_4 = "PayTime :" wide //weight: 1
        $x_1_5 = "\\Macromedia\\Flash Player\\#SharedObjects" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

