rule PWS_Win32_Dentuti_A_2147682599_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Dentuti.A"
        threat_id = "2147682599"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Dentuti"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 83 31 19 40 66 83 3c 42 00 8d 0c 42 75 f1}  //weight: 1, accuracy: High
        $x_1_2 = {80 74 04 10 5c 40 3b c6 7c f6}  //weight: 1, accuracy: High
        $x_1_3 = "End with status: {0x%X}, thId: [%d]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

