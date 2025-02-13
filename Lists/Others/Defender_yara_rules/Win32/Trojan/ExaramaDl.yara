rule Trojan_Win32_ExaramaDl_B_2147805820_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ExaramaDl.B"
        threat_id = "2147805820"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ExaramaDl"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "__shmem3_winpthreads_tdm_" ascii //weight: 1
        $x_1_2 = "<url> <filepath>" ascii //weight: 1
        $x_1_3 = "invoking Exaramel DLL via" ascii //weight: 1
        $x_1_4 = "[i] Downloading file:" ascii //weight: 1
        $x_1_5 = {83 e0 0f 41 c0 e8 04 83 c0 61 41 83 c0 41 88 42 ff 44 88 42 fe 4c 39 c9 75 d8 48 8d 05 ?? ?? ?? ?? b9 5f 00 00 00 48 8d 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

