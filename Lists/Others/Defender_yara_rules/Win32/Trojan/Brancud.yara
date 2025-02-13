rule Trojan_Win32_Brancud_A_2147627312_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Brancud.A"
        threat_id = "2147627312"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Brancud"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {68 30 00 05 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 00 ff d6 e9 ?? ?? ?? ?? 6a 01}  //weight: 10, accuracy: Low
        $x_10_2 = "Error (login): 0x10e0 The operator or administrator has refused the request" ascii //weight: 10
        $x_1_3 = "Software\\Allberst" ascii //weight: 1
        $x_1_4 = "Software\\RunB" ascii //weight: 1
        $x_1_5 = "Software\\RunC" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

