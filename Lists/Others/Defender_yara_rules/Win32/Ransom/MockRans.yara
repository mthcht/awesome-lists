rule Ransom_Win32_MockRans_XT_2147773325_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/MockRans.XT!MTB"
        threat_id = "2147773325"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "MockRans"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Executing a Mock Ransomware" ascii //weight: 1
        $x_1_2 = "Your files are encrypted" ascii //weight: 1
        $x_1_3 = "Please pay ransom using Bitcoin within 24hrs to get them back safely" ascii //weight: 1
        $x_1_4 = "This is a Mock Ransomware" ascii //weight: 1
        $x_1_5 = "\\MockRansomeware\\Debug\\MockRansomeware.pdb" ascii //weight: 1
        $x_1_6 = "Please_Read_Me @ .txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

