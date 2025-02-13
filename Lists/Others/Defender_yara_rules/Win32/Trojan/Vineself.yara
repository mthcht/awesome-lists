rule Trojan_Win32_Vineself_A_2147690776_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vineself.A"
        threat_id = "2147690776"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vineself"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8a 14 08 80 f2 ?? 88 11 41 4e 75}  //weight: 5, accuracy: Low
        $x_1_2 = "c:\\\\windows\\\\temp\\\\winfont32.cpl" wide //weight: 1
        $x_1_3 = "%c%d/%c%d%c%d%c%d/%c%d%c%d%c%d/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

