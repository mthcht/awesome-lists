rule VirTool_Win32_Binder_C_2147654668_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Binder.C"
        threat_id = "2147654668"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Binder"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 8d 94 24 ?? ?? 00 00 6a 1a 52 6a 00 ff 15 ?? ?? ?? ?? ff d6 bf ?? ?? ?? ?? 83 c9 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {5c 6d 69 63 72 6f 73 6f 66 74 5c 77 75 61 75 63 6c 74 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {3e 3e 4e 55 4c [0-5] 2f 63 20 64 65 6c 20 [0-2] 43 6f 6d 53 70 65 63}  //weight: 1, accuracy: Low
        $x_1_4 = "(*.pdf)|*.pdf|" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

