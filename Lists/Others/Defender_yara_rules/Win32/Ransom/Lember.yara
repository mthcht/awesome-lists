rule Ransom_Win32_Lember_PB_2147846547_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Lember.PB!MTB"
        threat_id = "2147846547"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Lember"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".lember" ascii //weight: 1
        $x_1_2 = "file are encrypted" ascii //weight: 1
        $x_1_3 = "erase you files" ascii //weight: 1
        $x_1_4 = "%desktop%\\ReadMe.txt" ascii //weight: 1
        $x_1_5 = "unlock your file" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

