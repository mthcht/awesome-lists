rule Ransom_Win32_VHDLocker_SK_2147752806_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/VHDLocker.SK!MTB"
        threat_id = "2147752806"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "VHDLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "HowToDecrypt.txt" wide //weight: 10
        $x_10_2 = "AEEAEE SET" wide //weight: 10
        $x_5_3 = "c:/data/prj/test" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

