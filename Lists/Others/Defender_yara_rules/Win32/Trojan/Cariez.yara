rule Trojan_Win32_Cariez_A_2147627426_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cariez.A"
        threat_id = "2147627426"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cariez"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "%s\\Rundll32.exe %s,DllUnregisterServer" ascii //weight: 1
        $x_1_2 = {68 a1 84 00 00 e8 ?? ?? ?? ?? 83 c4 04}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 00 8d 04 40 8d 04 80 8d 04 80 8d 04 80 8d 04 80 8d 04 80 c1 e0 05 50 68 00 10 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

