rule Virus_Win32_Lamechi_2147626663_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Lamechi"
        threat_id = "2147626663"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Lamechi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e8 2d 00 00 00 87 06 03 f2 03 fa e2 f0 68 6f 6e 00 00 68 75 72 6c 6d 54 ff 55 fc 59 59 ff 37 50 e8 0d 00 00 00 87 06 61 c9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

