rule Ransom_Win32_SepSys_PA_2147750958_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/SepSys.PA!MTB"
        threat_id = "2147750958"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "SepSys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ATTENTION! Your computer has been infected by sepSys!" ascii //weight: 1
        $x_1_2 = ".inisepSys" ascii //weight: 1
        $x_1_3 = "Your files have been encrypted with a random key" ascii //weight: 1
        $x_1_4 = "\\virusTests\\sepSys" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

