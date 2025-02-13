rule VirTool_Win32_DllInjector_C_2147759306_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DllInjector.C"
        threat_id = "2147759306"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DllInjector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 00}  //weight: 1, accuracy: High
        $x_1_2 = {81 f9 5b bc 4a 6a 0f 85}  //weight: 1, accuracy: High
        $x_1_3 = {8e 4e 0e ec 74 ?? ?? ?? ?? aa fc 0d 7c 74 ?? ?? ?? ?? 54 ca af 91 74 ?? ?? ?? ?? ef ce e0 60}  //weight: 1, accuracy: Low
        $x_1_4 = {81 f9 5d 68 fa 3c 0f 85 ?? 00 00 00}  //weight: 1, accuracy: Low
        $x_1_5 = {b8 0a 4c 53 75}  //weight: 1, accuracy: High
        $x_1_6 = {3c 33 c9 41 b8 00 30 00 00 ?? 03 ?? 44 8d 49 40 [0-16] ff d5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

