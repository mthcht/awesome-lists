rule Trojan_Win32_Audhi_B_2147642273_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Audhi.B"
        threat_id = "2147642273"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Audhi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 0b 44 72 69 76 65 72 50 72 6f 63 00 68 ?? ?? ?? 10 ff 35 ?? ?? ?? 10 e8 ?? ?? ?? ?? a3 ?? ?? ?? 10 eb 0b}  //weight: 1, accuracy: Low
        $x_1_2 = {eb 0b 61 75 78 4d 65 73 73 61 67 65 00 68 ?? ?? ?? 10 ff 35 ?? ?? ?? 10 e8}  //weight: 1, accuracy: Low
        $x_1_3 = "%windir%\\system32\\wdmaud.drv" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

