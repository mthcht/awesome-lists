rule Trojan_Win32_Kalavus_B_2147955838_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kalavus.B"
        threat_id = "2147955838"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kalavus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "\\valakmalware_text.txt" wide //weight: 1
        $x_1_3 = "wget" wide //weight: 1
        $x_1_4 = " -o " wide //weight: 1
        $x_1_5 = "wscript.exe" wide //weight: 1
        $x_1_6 = "//E:jscript" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Kalavus_C_2147955839_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kalavus.C"
        threat_id = "2147955839"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kalavus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "\\project1.htm" wide //weight: 5
        $x_5_2 = "\\Temp\\U.tmp" wide //weight: 5
        $x_2_3 = "powershell" wide //weight: 2
        $x_2_4 = " -c wget " wide //weight: 2
        $x_2_5 = " -o " wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_2_*))) or
            ((2 of ($x_5_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

