rule Worm_Win32_Vexral_A_2147649386_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vexral.A"
        threat_id = "2147649386"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vexral"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6a 40 68 00 30 00 00 ff 76 50 ff 76 34 ff 75 ?? ff [0-2] 3b c3}  //weight: 10, accuracy: Low
        $x_1_2 = "#BOT#URLDownload" ascii //weight: 1
        $x_1_3 = {66 61 63 65 62 6f 6f 6b 2e [0-4] 2f 61 6a 61 78 2f 63 68 61 74 2f 73 65 6e 64 2e 70 68 70}  //weight: 1, accuracy: Low
        $x_1_4 = "login_password=" ascii //weight: 1
        $x_1_5 = "GTalk Instant Message" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

