rule Trojan_Win32_Pliskal_A_2147725180_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pliskal.A!bit"
        threat_id = "2147725180"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pliskal"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8b 45 08 89 04 24 e8 ?? ?? ?? ?? 3b 45 ?? 76 3b 8b 5d ?? 81 c3 ?? ?? ?? ?? 8b 45 ?? 8b 4d ?? 01 c1 8b 55 ?? 8d 45 ?? 89 45 ?? 89 d0 8b 75 ?? ba ?? ?? ?? ?? f7 36 0f b6 92 ?? ?? ?? ?? 0f b6 01 28 d0 88 03 8d 45 ?? ff 00 eb}  //weight: 4, accuracy: Low
        $x_1_2 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "netsh advfirewall firewall add rule name" ascii //weight: 1
        $x_1_4 = ":Zone.Identifier" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pliskal_C_2147726670_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pliskal.C"
        threat_id = "2147726670"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pliskal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "firewall add rule name=\"Quant\" program=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

