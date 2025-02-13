rule Backdoor_Win32_Warring_B_2147632379_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Warring.B"
        threat_id = "2147632379"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Warring"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 68 04 00 00 98 8b 46 04 50 e8 ?? ?? ?? ?? 40 74 02 b3 01}  //weight: 1, accuracy: Low
        $x_1_2 = {77 61 72 72 69 6e 67 2e 2e 2e 00 00 63 6f 6e 6e 65 63 74 20 31 32 37 2e 30 2e 30 2e 31 3a 31 32 33 34 35 21}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

