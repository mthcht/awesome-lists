rule Trojan_Win32_NinSky_A_2147709056_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NinSky.A"
        threat_id = "2147709056"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NinSky"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 00 72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 00 00 5c 00 52 00 65 00 73 00 4e 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 00 00 52 00 75 00 6e 00}  //weight: 1, accuracy: High
        $x_1_2 = {45 00 75 00 70 00 64 00 61 00 74 00 65 00 00 00 53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00}  //weight: 1, accuracy: High
        $x_1_3 = "\\WORK\\PROJECT\\InfInstallBypassUAC\\Release\\BypassUAC.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

