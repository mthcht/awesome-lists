rule PWS_Win32_Brothef_A_2147629532_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Brothef.A"
        threat_id = "2147629532"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Brothef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 61 73 73 77 6f 72 64 5f 76 61 6c 75 65 00}  //weight: 1, accuracy: High
        $x_1_2 = "SELECT * FROM moz_logins" ascii //weight: 1
        $x_1_3 = {8a 44 18 ff 24 0f 8b 55 f8 8a 54 32 ff 80 e2 0f 32 c2 88 45 f3 8d 45 fc e8 ?? ?? ?? ?? 8b 55 fc 8a 54 1a ff 80 e2 f0 8a 4d f3 02 d1 88 54 18 ff 46 8b 45 f8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

