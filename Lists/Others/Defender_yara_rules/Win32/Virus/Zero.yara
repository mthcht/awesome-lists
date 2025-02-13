rule Virus_Win32_Zero_RS_2147910293_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Zero.RS!MTB"
        threat_id = "2147910293"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Zero"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {69 c0 01 01 00 00 0f b6 c9 03 c1 c1 e1 10 8d 76 01 33 c1 8a 0e 84 c9 75 e7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

