rule Trojan_Win32_Powenctec_C_2147927391_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powenctec.C"
        threat_id = "2147927391"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powenctec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "powershell.exe" wide //weight: 10
        $x_10_2 = "aWV4IChpd3IgJ2h0dHBzOi8vZHduZmlsZTI3LmItY2RuLm5l" wide //weight: 10
        $x_1_3 = "-w hidden" wide //weight: 1
        $x_1_4 = "frombase64string(" wide //weight: 1
        $x_1_5 = "[text.encoding]::utf8.getstring(" wide //weight: 1
        $x_1_6 = "| iex" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

