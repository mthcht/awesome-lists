rule Trojan_Win32_Clickfix_PRA_2147961551_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Clickfix.PRA!MTB"
        threat_id = "2147961551"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Clickfix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "powershell.exe" wide //weight: 10
        $x_10_2 = "Verif" wide //weight: 10
        $x_5_3 = ".txt" wide //weight: 5
        $x_2_4 = "-wi" wide //weight: 2
        $x_2_5 = "iex" wide //weight: 2
        $x_2_6 = "get-command I*-We*" wide //weight: 2
        $x_2_7 = "wget" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

