rule Trojan_Win32_BlackCatRsm_A_2147914869_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BlackCatRsm.A"
        threat_id = "2147914869"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackCatRsm"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "--no-prop-servers" ascii //weight: 1
        $x_1_2 = "--no-vm-snapshot-kill" ascii //weight: 1
        $x_1_3 = {64 72 6f 70 2d 64 72 61 67 [0-80] 64 72 6f 70 2d 74 61 72 67 65 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

