rule Worm_Win32_Cubspewt_A_2147622796_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Cubspewt.A"
        threat_id = "2147622796"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Cubspewt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 6f 8d 95 ?? ?? ?? ?? 52 ff 15 ?? ?? ?? ?? 6a 70 8d 85 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 6a 75 8d 8d ?? ?? ?? ?? 51 ff 15 ?? ?? ?? ?? 6a 73}  //weight: 2, accuracy: Low
        $x_2_2 = "[UPDATED]: I am up2date!" wide //weight: 2
        $x_2_3 = "[INSTALLED]: I am new!" wide //weight: 2
        $x_2_4 = "[JOINED]: I am here ;)" wide //weight: 2
        $x_1_5 = "%botdir%" wide //weight: 1
        $x_1_6 = "autorun.inf" wide //weight: 1
        $x_1_7 = "shell\\Autoplay\\command=" wide //weight: 1
        $x_1_8 = "ping 1.2.3.4 -l 65500 -n 1 -w 2500>nul" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

