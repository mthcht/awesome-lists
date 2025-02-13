rule Trojan_Win32_Kraptik_B_2147630498_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kraptik.gen!B"
        threat_id = "2147630498"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kraptik"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 c6 8c 99 07 bb 56 33 db 52 53 ff 15 ?? ?? 40 00}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 05 21 d9 8b d1 bf 3d 46 04 00 57 ff 15 ?? ?? 40 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

