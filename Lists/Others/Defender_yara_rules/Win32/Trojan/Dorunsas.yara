rule Trojan_Win32_Dorunsas_S_2147729665_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dorunsas.S"
        threat_id = "2147729665"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dorunsas"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "aresi.xyz" wide //weight: 1
        $x_1_2 = "atakara.bid" wide //weight: 1
        $x_1_3 = "YZNA175IapGqBmBSJq17JG" wide //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

