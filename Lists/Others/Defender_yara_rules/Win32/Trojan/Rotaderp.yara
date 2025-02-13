rule Trojan_Win32_Rotaderp_B_2147767221_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rotaderp.B"
        threat_id = "2147767221"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rotaderp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/c if not %computername% == DESKTOP-QO5QU33" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rotaderp_B_2147767221_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rotaderp.B"
        threat_id = "2147767221"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rotaderp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/c if not %computername% == DESKTOP-QO5QU33" wide //weight: 1
        $x_1_2 = "RunProgram" wide //weight: 1
        $x_2_3 = "smart-soft.herokuapp.com/setup" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

