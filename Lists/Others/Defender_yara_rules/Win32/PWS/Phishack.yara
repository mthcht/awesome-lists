rule PWS_Win32_Phishack_C_2147697471_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Phishack.C"
        threat_id = "2147697471"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Phishack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 00 65 00 62 00 4d 00 6f 00 6e 00 65 00 79 00 48 00 61 00 63 00 6b 00 00 1a 00 43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = ".soulstream.ru" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

