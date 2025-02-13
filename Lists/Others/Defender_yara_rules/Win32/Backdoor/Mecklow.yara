rule Backdoor_Win32_Mecklow_A_2147641447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Mecklow.A"
        threat_id = "2147641447"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Mecklow"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 cb 8a 5d 0a 88 4d fd 8a cb c0 e2 02 c0 e9 06 02 d1 80 e3 3f 3b 7d 14 88 5d ff}  //weight: 5, accuracy: High
        $x_1_2 = {99 b9 10 cd 0e 00 f7 f9 81 c2 10 cd 0e 00 52}  //weight: 1, accuracy: High
        $x_1_3 = {ff ff 2a c6 85 ?? ?? ff ff 2a c6 85 ?? ?? ff ff 5b c6 85 ?? ?? ff ff 53 c6 85 ?? ?? ff ff 54}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

