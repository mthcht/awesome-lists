rule Trojan_Win32_SusBisodown_A_2147955537_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusBisodown.A"
        threat_id = "2147955537"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusBisodown"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "reg.exe add " ascii //weight: 1
        $x_1_2 = "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = " /t REG_EXPAND_SZ /v" ascii //weight: 1
        $x_1_4 = "PHIME2010ASYNC" ascii //weight: 1
        $x_1_5 = " /f" wide //weight: 1
        $x_1_6 = "Prefetch" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

