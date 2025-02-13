rule Worm_Win32_Najufa_A_2147688802_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Najufa.A"
        threat_id = "2147688802"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Najufa"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6f 24 00 00 0a 08 6f 25 00 00 0a 02 7b 0b 00 00 04 28 26 00 00 0a 17 28 27 00 00 0a}  //weight: 1, accuracy: High
        $x_1_2 = "!.My Video.scr" wide //weight: 1
        $x_1_3 = "CreateObject(\"nj.W\").W(\"x\")" wide //weight: 1
        $x_1_4 = "netsh firewall delete allowedprogram" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

