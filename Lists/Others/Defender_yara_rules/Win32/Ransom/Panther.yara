rule Ransom_Win32_Panther_G_2147759266_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Panther.G!MTB"
        threat_id = "2147759266"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Panther"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "panther123456789" ascii //weight: 1
        $x_1_2 = "987654321panther" ascii //weight: 1
        $x_1_3 = "#bitkey" ascii //weight: 1
        $x_1_4 = "LOCKED_README" ascii //weight: 1
        $x_1_5 = "vssadmin delete shadows /all /quiet" ascii //weight: 1
        $x_1_6 = "wmic shadowcopy delete /nointeractive" ascii //weight: 1
        $x_1_7 = ".panther" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

