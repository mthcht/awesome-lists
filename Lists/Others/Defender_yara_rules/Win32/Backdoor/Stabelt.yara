rule Backdoor_Win32_Stabelt_A_2147726336_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Stabelt.A!bit"
        threat_id = "2147726336"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Stabelt"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "title.bestdeals.at" wide //weight: 10
        $x_1_2 = {00 00 5c 00 6d 00 6d 00 74 00 61 00 73 00 6b 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: High
        $x_1_3 = "Mozilla/4.0" wide //weight: 1
        $x_1_4 = "cmd command %d" ascii //weight: 1
        $x_1_5 = "guadao beng kui" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

