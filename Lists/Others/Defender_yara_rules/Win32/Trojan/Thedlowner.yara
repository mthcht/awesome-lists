rule Trojan_Win32_Thedlowner_A_2147637366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Thedlowner.A"
        threat_id = "2147637366"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Thedlowner"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NUR\\NOISREVTNERRUC\\SWODNIW\\TFOSORCIM\\ERAWTFOS" ascii //weight: 1
        $x_1_2 = {56 65 72 79 49 6d 70 6f 72 74 61 6e 74 57 69 6e 64 6f 77 73 46 69 6c 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {4e 61 6f 20 74 65 6d 20 4e 41 44 41 00}  //weight: 1, accuracy: High
        $x_1_4 = {67 68 68 6c 6c 73 79 73 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_5 = "\\loaderIni.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

