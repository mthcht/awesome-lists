rule Trojan_Win32_Myspamce_A_2147607411_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Myspamce.A"
        threat_id = "2147607411"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Myspamce"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {ff d7 8b 45 d4 68 ?? ?? 40 00 50 ff 15 ?? ?? 40 00 59 85 c0 59 75 6e 39 5d c4 75 69}  //weight: 3, accuracy: Low
        $x_2_2 = "?a=%s&b=%s" ascii //weight: 2
        $x_2_3 = "myspacetube.net" ascii //weight: 2
        $x_1_4 = {f7 f1 50 30 b5 98 cf 11 bb 82 00 aa 00 bd ce 0b 6d 79 73 70 61 63 65 2e 63 6f 6d 00}  //weight: 1, accuracy: High
        $x_1_5 = {66 72 69 65 6e 64 69 64 3d 36 32 32 31 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

