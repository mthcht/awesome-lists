rule Trojan_Win32_Brolocker_A_2147632488_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Brolocker.A"
        threat_id = "2147632488"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Brolocker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 6e 64 53 74 31 5c 44 65 66 61 75 6c 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {45 52 52 4f 52 20 68 61 73 20 6f 63 63 75 72 65 64 21 20 53 65 6e 64 69 6e 67 20 45 72 72 6f 72 20 52 65 70 6f 72 74 20 2e 2e 2e 00}  //weight: 1, accuracy: High
        $x_1_3 = {8b f0 68 80 ee 36 00 ff 15 ?? ?? 40 00 4e 75 f2 83 3d ?? ?? 40 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

