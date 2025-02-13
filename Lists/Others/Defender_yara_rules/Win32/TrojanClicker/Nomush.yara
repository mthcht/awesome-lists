rule TrojanClicker_Win32_Nomush_A_2147630361_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Nomush.A"
        threat_id = "2147630361"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Nomush"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 74 72 6c 4b 65 79 00 44 6f 77}  //weight: 1, accuracy: High
        $x_1_2 = {2f 6e 6f 63 61 73 68 2f 75 72 6c 73 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_3 = "nocashemu" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

