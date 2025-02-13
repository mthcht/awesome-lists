rule Worm_Win32_ShadowWhite_A_2147648359_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/ShadowWhite.A"
        threat_id = "2147648359"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "ShadowWhite"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {62 6f 74 6e 65 74 [0-2] 6b 61 6e 61 61 6c 00}  //weight: 1, accuracy: Low
        $x_1_2 = {57 68 69 74 65 [0-2] 53 68 61 64 6f 77}  //weight: 1, accuracy: Low
        $x_1_3 = "HTTP Flood" wide //weight: 1
        $x_1_4 = "UDP Flood" wide //weight: 1
        $x_1_5 = "SYN Flood" wide //weight: 1
        $x_1_6 = "[INFECTED]: I am infected!" wide //weight: 1
        $x_1_7 = "[JOINED]: I am here ;)" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

