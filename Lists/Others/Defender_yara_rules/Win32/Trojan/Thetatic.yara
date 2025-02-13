rule Trojan_Win32_Thetatic_A_2147641168_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Thetatic.A"
        threat_id = "2147641168"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Thetatic"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {eb 04 49 30 24 39 83 f9 00 77 f7}  //weight: 2, accuracy: High
        $x_2_2 = {eb 15 80 3e 5c 75 09 c6 07 5c 47 c6 07 5c eb 04}  //weight: 2, accuracy: High
        $x_1_3 = "cstype=server" ascii //weight: 1
        $x_1_4 = "command=result" ascii //weight: 1
        $x_1_5 = "vals[i]^keycode" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

