rule Trojan_Win32_Zoxpng_A_2147689336_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zoxpng.A"
        threat_id = "2147689336"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zoxpng"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "http://%s/%04d-%02d/%04d%02d%02d%02d%02d%02d.png" ascii //weight: 1
        $x_1_2 = "http://%s/imgres?q=" ascii //weight: 1
        $x_1_3 = {42 36 34 3a 5b 25 73 5d [0-16] 53 74 65 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zoxpng_B_2147689337_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zoxpng.B"
        threat_id = "2147689337"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zoxpng"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5f 69 69 73 6b 69 6c 6c [0-16] 43 6c 65 61 72 46 69 6c 65}  //weight: 1, accuracy: Low
        $x_1_2 = {53 74 61 72 74 53 68 65 6c 6c 00 00 50 61 73 73 77 6f 72 64 3a}  //weight: 1, accuracy: High
        $x_2_3 = {43 6c 65 61 72 46 69 6c 65 00 53 74 61 72 74 53 68 65 6c 6c 00 67 5f 69 69 73 65 78 69 74 00 67 5f 69 69 73 6b 69 6c 6c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

