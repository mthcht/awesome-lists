rule Backdoor_Win32_Truebot_A_2147724323_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Truebot.A"
        threat_id = "2147724323"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Truebot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 00 74 00 72 00 6a 00 79 00 79 00 74 00 72 00 6e 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {68 00 74 00 63 00 6e 00 66 00 68 00 6e 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {79 00 74 00 6e 00 70 00 66 00 6c 00 66 00 79 00 62 00 71 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {26 00 62 00 78 00 79 00 3d 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = "Upsss. Process exit code" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

