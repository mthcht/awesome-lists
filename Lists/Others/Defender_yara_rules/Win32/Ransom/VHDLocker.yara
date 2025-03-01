rule Ransom_Win32_VhdLocker_PA_2147761066_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/VhdLocker.PA!MTB"
        threat_id = "2147761066"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "VhdLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".vhd" wide //weight: 1
        $x_1_2 = "sc stop \"Microsoft Exchange" ascii //weight: 1
        $x_1_3 = "HowToDecrypt.txt" wide //weight: 1
        $x_1_4 = "AEEAEE SET" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

