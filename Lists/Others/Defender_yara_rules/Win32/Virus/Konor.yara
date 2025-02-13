rule Virus_Win32_Konor_RS_2147910908_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Konor.RS!MTB"
        threat_id = "2147910908"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Konor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 04 39 33 c6 25 ff 00 00 00 c1 ee 08 33 b4 85 fc fb ff ff 41 3b ca 72 e6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

