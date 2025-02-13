rule Tool_Win32_MpTestModerateRemove_2147697698_0
{
    meta:
        author = "defender2yara"
        detection_name = "Tool:Win32/MpTestModerateRemove"
        threat_id = "2147697698"
        type = "Tool"
        platform = "Win32: Windows 32-bit platform"
        family = "MpTestModerateRemove"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "4bc7a689-9aad-4ca5-9030-ca5319e04b70" ascii //weight: 1
        $x_1_2 = "b6fe82e5-d5b9-4062-9004-3d43aa73d89c" ascii //weight: 1
        $x_1_3 = "8d06266e-e9cf-453c-98db-95160f5b8ee7" ascii //weight: 1
        $x_1_4 = "77cb1e20-4510-4096-9531-efd8e55b5bcf" ascii //weight: 1
        $x_1_5 = "312b2df8-fa68-4893-9f72-f1fbbf2a9b4c" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

