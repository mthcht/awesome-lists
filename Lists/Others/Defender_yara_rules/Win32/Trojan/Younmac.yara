rule Trojan_Win32_Younmac_2147497188_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Younmac"
        threat_id = "2147497188"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Younmac"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 06 6a 01 6a 02 e8 ?? ?? ?? ?? 8b d8 83 fb ff [0-3] 47 83 ff 0a 0f 8f ?? ?? 00 00 68 00 a0 00 00 e8 ?? ?? ?? ?? eb}  //weight: 2, accuracy: Low
        $x_1_2 = "\"C:\\Windows\\iexplore.exe\"" ascii //weight: 1
        $x_1_3 = "c:\\autoexec.dat" ascii //weight: 1
        $x_1_4 = {53 4c 4f 57 4e 45 54 00}  //weight: 1, accuracy: High
        $x_1_5 = {75 6e 70 61 73 73 72 75 6e 2e 63 66 6d 20 48 54 54 50 2f 31 00}  //weight: 1, accuracy: High
        $x_1_6 = "Win32Ldr.Dll" ascii //weight: 1
        $x_1_7 = {4d 61 63 5f 53 6e 69 66 66 5f 46 69 6c 65 4d 61 70 00}  //weight: 1, accuracy: High
        $x_1_8 = "YONG_Mac_Sniff_" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

