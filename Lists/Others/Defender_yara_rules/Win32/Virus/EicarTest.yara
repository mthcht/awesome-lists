rule Virus_Win32_EicarTest_A_2147953389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/EicarTest.A!MTB"
        threat_id = "2147953389"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "EicarTest"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "S/4nS/4*S/4" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

