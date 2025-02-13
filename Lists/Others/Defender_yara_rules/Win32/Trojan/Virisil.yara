rule Trojan_Win32_Virisil_A_2147708389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Virisil.A"
        threat_id = "2147708389"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Virisil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4b 69 6c 6c 54 73 6b 4d 6e 67 72 00}  //weight: 1, accuracy: High
        $x_1_2 = "HARD DRIVE vv111 CORRUPTION" wide //weight: 1
        $x_1_3 = "This window will close in 3 secounds" wide //weight: 1
        $x_1_4 = "\\vr.exe" wide //weight: 1
        $x_1_5 = "viriMemory" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

