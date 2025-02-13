rule Virus_Win32_Mikasa_A_2147681362_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Mikasa.A"
        threat_id = "2147681362"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Mikasa"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 51 52 51 54 53 50 51 51 6a 02 51 51 6a 03 52 ff 55 30 50 96 ff 55 00 56 ff 55 34 ff 55 04 ff 55 18 cc 4d 00 5a 01 50}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

