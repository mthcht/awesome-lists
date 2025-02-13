rule Ransom_Win32_XYLocker_2147812627_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/XYLocker!MTB"
        threat_id = "2147812627"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "XYLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Files Encrypted" wide //weight: 1
        $x_1_2 = "encrypted by XY Locker" ascii //weight: 1
        $x_1_3 = "hours to pay" ascii //weight: 1
        $x_1_4 = "in Bitcoin to the adress" ascii //weight: 1
        $x_1_5 = "then ALL your files will be gone" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

