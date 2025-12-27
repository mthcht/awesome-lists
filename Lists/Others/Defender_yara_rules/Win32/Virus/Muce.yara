rule Virus_Win32_Muce_EM_2147954411_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Muce.EM!MTB"
        threat_id = "2147954411"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Muce"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {33 d2 f7 f7 8a 04 16 30 03 43 41}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

