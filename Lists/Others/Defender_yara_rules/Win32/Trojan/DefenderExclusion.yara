rule Trojan_Win32_DefenderExclusion_A_2147789149_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DefenderExclusion.A"
        threat_id = "2147789149"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DefenderExclusion"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "WMIC.exe" wide //weight: 10
        $x_10_2 = {6e 00 61 00 6d 00 65 00 73 00 70 00 61 00 63 00 65 00 3a 00 [0-32] 5c 00 6d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 64 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 00 20 00 63 00 6c 00 61 00 73 00 73 00 20 00 6d 00 73 00 66 00 74 00 5f 00 6d 00 70 00 70 00 72 00 65 00 66 00 65 00 72 00 65 00 6e 00 63 00 65 00}  //weight: 10, accuracy: Low
        $x_10_3 = "call Add ExclusionPath" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

