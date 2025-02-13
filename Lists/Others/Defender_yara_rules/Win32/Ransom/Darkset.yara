rule Ransom_Win32_Darkset_CCIQ_2147926242_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Darkset.CCIQ!MTB"
        threat_id = "2147926242"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Darkset"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {54 6f 75 63 68 4d 65 4e 6f 74 5f 2e 74 78 74 2e 5b [0-15] 5d 2e 44 41 52 4b 53 45 54}  //weight: 5, accuracy: Low
        $x_1_2 = ".DARKSET\\DefaultIcon" ascii //weight: 1
        $x_1_3 = "vssadmin.exe delete shadows /all /quiet" ascii //weight: 1
        $x_5_4 = "All your files have been encrypted" ascii //weight: 5
        $x_1_5 = ".DARKSET" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

