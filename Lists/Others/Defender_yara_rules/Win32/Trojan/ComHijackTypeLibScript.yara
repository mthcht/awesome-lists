rule Trojan_Win32_ComHijackTypeLibScript_A_2147971732_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ComHijackTypeLibScript.A"
        threat_id = "2147971732"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ComHijackTypeLibScript"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "75"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "reg.exe" wide //weight: 20
        $x_5_2 = "add " wide //weight: 5
        $x_20_3 = "\\Software\\Classes\\TypeLib\\" wide //weight: 20
        $x_10_4 = " REG_SZ " wide //weight: 10
        $x_20_5 = "script:" wide //weight: 20
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

