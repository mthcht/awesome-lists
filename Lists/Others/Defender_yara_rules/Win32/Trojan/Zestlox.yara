rule Trojan_Win32_Zestlox_A_2147614113_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zestlox.A"
        threat_id = "2147614113"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zestlox"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {54 69 6d 65 44 6c 6c 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 00 53 76 63 68 6f 73 74 45 6e 74 72 79 5f 57 33 32 54 69 6d 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {69 6e 73 73 2f 4e 65 77 56 65 72 2e 74 78 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zestlox_C_2147620379_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zestlox.C"
        threat_id = "2147620379"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zestlox"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hjob123" ascii //weight: 1
        $x_1_2 = ".cn/inss/NewVer" ascii //weight: 1
        $x_1_3 = "SvchostEntry_W32Time" ascii //weight: 1
        $x_1_4 = "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\W32Time" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

