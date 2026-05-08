rule Trojan_Win32_SuspPeristInProgDat_Z_2147968839_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspPeristInProgDat.Z!MTB"
        threat_id = "2147968839"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspPeristInProgDat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "reg.exe\" add" wide //weight: 1
        $x_1_2 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_3 = "wscript.exe" wide //weight: 1
        $x_1_4 = {70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 64 00 61 00 74 00 61 00 5c 00 6d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 [0-255] 2e 00 76 00 62 00 73 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

