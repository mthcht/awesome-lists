rule Ransom_Win32_Silvertor_SK_2147760699_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Silvertor.SK!MTB"
        threat_id = "2147760699"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Silvertor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "silvertor" ascii //weight: 2
        $x_2_2 = "Your files will be fried in" ascii //weight: 2
        $x_2_3 = "\\Start Menu\\Programs\\Startup\\README.html" ascii //weight: 2
        $x_15_4 = "vssadmin.exe Delete Shadows /All /Quiet" ascii //weight: 15
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_15_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

