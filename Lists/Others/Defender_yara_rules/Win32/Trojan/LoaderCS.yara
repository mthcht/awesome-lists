rule Trojan_Win32_LoaderCS_ZZ_2147814425_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LoaderCS.ZZ"
        threat_id = "2147814425"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LoaderCS"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c0 40 3d 0b 00 66 0f f8 c1 0f 11 80 07 00 0f 11 80 0b 00 66 0f f8 c1 0f 11 80 07 00 0f 11 80 0b 00 66 0f f8 c1 0f 11 80 07 00 0f 11 80 0b 00 66 0f f8 c1 0f 11 80 07 00 0f 11 80}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

