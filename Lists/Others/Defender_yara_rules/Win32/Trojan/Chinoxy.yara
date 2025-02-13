rule Trojan_Win32_Chinoxy_A_2147644034_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chinoxy.A"
        threat_id = "2147644034"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chinoxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@SET SLEEP=ping 127.0.0.1 -n" ascii //weight: 1
        $x_1_2 = "@del fsewewfrtretrwwe.ewe" ascii //weight: 1
        $x_1_3 = "@echo kjyuyutuytnfgfhghd>>fsewewfrtretrwwe.ewe" ascii //weight: 1
        $x_1_4 = {00 43 6f 6e 74 72 6f 6c 53 65 72 76 69 63 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Chinoxy_B_2147717059_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chinoxy.B!bit"
        threat_id = "2147717059"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chinoxy"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 61 73 6b 6b 69 6c 6c 2e 65 78 65 20 2f 46 20 2f 49 4d [0-48] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_2 = "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services" ascii //weight: 1
        $x_1_3 = "@SET SLEEP=ping 127.0.0.1 -n" ascii //weight: 1
        $x_1_4 = "@del fsewewfrtretrwwe.ewe" ascii //weight: 1
        $x_1_5 = "@echo kjyuyutuytnfgfhghd>>fsewewfrtretrwwe.ewe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Chinoxy_PA_2147751943_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chinoxy.PA!MSR"
        threat_id = "2147751943"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chinoxy"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@reg DELETE HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Hux91 /f" ascii //weight: 1
        $x_1_2 = "reg.exe add HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Hux91 /t REG_SZ /d %s /f" ascii //weight: 1
        $x_1_3 = "\\tasks\\infokey.dat" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

