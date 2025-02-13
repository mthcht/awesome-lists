rule Trojan_Win32_Surinfub_A_2147679376_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Surinfub.A"
        threat_id = "2147679376"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Surinfub"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {24 0f fe c8 30 06 46 4f eb d1}  //weight: 1, accuracy: High
        $x_1_2 = {72 65 67 73 76 72 33 32 00 2f 73 20 22 25 73 22}  //weight: 1, accuracy: High
        $x_1_3 = {74 6b 83 65 1c 00 8b 08 8d 55 1c 52 50 ff 91 b0 01 00 00 83 7d 1c 00 74 4b 83 ff 6a 74 08 81 ff fc 00 00 00 75 2a}  //weight: 1, accuracy: High
        $x_1_4 = "function(){var d = document, h = d.getElementsByTagName('head')[0], s = d.createElement('script');" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

