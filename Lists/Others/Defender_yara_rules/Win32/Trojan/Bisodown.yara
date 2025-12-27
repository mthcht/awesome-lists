rule Trojan_Win32_Bisodown_A_2147954072_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bisodown.A"
        threat_id = "2147954072"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bisodown"
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
        $n_1_7 = "9453e881-26a8-4973-ba2e-76269e901d0f" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

