rule Backdoor_Win32_Esserv_2147600102_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Esserv"
        threat_id = "2147600102"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Esserv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 01 00 00 00 85 c0 74 1d 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 68 80 4f 12 00 ff 15 ?? ?? ?? ?? eb da}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

