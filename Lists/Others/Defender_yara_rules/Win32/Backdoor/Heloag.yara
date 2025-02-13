rule Backdoor_Win32_Heloag_A_2147628547_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Heloag.A"
        threat_id = "2147628547"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Heloag"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {83 c8 80 40 88 04 3e 46 83 fe 64 7c e5 be 02 00 00 00}  //weight: 3, accuracy: High
        $x_1_2 = "helloAgent" ascii //weight: 1
        $x_1_3 = "%d-%d-%d-%d-%d.htm" ascii //weight: 1
        $x_1_4 = "%s\\%d-%d-%d-%d-%d.exe" ascii //weight: 1
        $x_1_5 = {68 89 13 00 00 68 ?? ?? ?? ?? 8b 48 10 51 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Heloag_B_2147632888_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Heloag.B"
        threat_id = "2147632888"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Heloag"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {83 c8 80 40 88 44 3c ?? 47 83 ff 02 7c e4}  //weight: 3, accuracy: Low
        $x_1_2 = "helloAgent" ascii //weight: 1
        $x_1_3 = "%d-%d-%d-%d-%d.htm" ascii //weight: 1
        $x_1_4 = "%s\\%d-%d-%d-%d-%d.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

