rule Worm_Win32_VBInject_GXZ_2147921668_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/VBInject.GXZ!MTB"
        threat_id = "2147921668"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {4e 48 82 31 8a 74 ?? 22 7c 3b 80 94 07}  //weight: 10, accuracy: Low
        $x_1_2 = "nEwb0Rn.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

