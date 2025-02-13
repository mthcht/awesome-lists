rule Trojan_Win32_Fakon_A_2147694847_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fakon.A"
        threat_id = "2147694847"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fakon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e [0-8] 22 20 61 75 74 6f}  //weight: 1, accuracy: Low
        $x_1_2 = "\\Servce\\release\\Servce.pdb" ascii //weight: 1
        $x_1_3 = "\\Syspiao\\Release\\Syspiao.pdb" ascii //weight: 1
        $x_1_4 = "&payid=" ascii //weight: 1
        $x_1_5 = "&Hide" wide //weight: 1
        $x_1_6 = "Mail system DLL is invalid" wide //weight: 1
        $x_1_7 = "Servce.exe" wide //weight: 1
        $x_1_8 = "%1: %2" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

