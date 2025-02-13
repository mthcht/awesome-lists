rule TrojanClicker_Win32_Rongvhin_C_2147683955_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Rongvhin.C"
        threat_id = "2147683955"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Rongvhin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 7e 48 74 3f 48 75 2a 8b 7c 24 14 56 6a 02 68 04 02 00 00 57 e8}  //weight: 1, accuracy: High
        $x_1_2 = "API-Guide test program" ascii //weight: 1
        $x_1_3 = "Loading,Please Wait........" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

