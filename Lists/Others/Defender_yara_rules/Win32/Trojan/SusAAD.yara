rule Trojan_Win32_SusAAD_A_2147954099_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusAAD.A"
        threat_id = "2147954099"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusAAD"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_2 = "SharpAwareness.exe" ascii //weight: 1
        $x_1_3 = "SharpADUserIP.exe" ascii //weight: 1
        $x_1_4 = "SharpWnfDump.exe -d -r" ascii //weight: 1
        $n_1_5 = "a453e881-26a8-4973-bi2e-76269e901d0a" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (2 of ($x*))
}

rule Trojan_Win32_SusAAD_B_2147954100_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusAAD.B"
        threat_id = "2147954100"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusAAD"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "nltest " ascii //weight: 1
        $x_1_2 = "/domain_trusts" ascii //weight: 1
        $n_1_3 = "a453e881-26a8-4973-bj2e-76269e901d0a" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SusAAD_C_2147954101_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusAAD.C"
        threat_id = "2147954101"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusAAD"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "whoami.exe" ascii //weight: 1
        $x_1_2 = "/all" ascii //weight: 1
        $x_1_3 = "/groups" ascii //weight: 1
        $n_1_4 = "a453e881-26a8-4973-bk2e-76269e901d0a" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (2 of ($x*))
}

rule Trojan_Win32_SusAAD_D_2147954102_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusAAD.D"
        threat_id = "2147954102"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusAAD"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Reconerator.exe" ascii //weight: 1
        $x_1_2 = "AppData\\Local\\Temp" ascii //weight: 1
        $n_1_3 = "a453e881-26a8-4973-bl2e-76269e901d0a" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

