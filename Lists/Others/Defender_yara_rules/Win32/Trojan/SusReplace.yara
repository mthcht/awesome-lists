rule Trojan_Win32_SusReplace_Z_2147955911_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusReplace.Z!MTB"
        threat_id = "2147955911"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusReplace"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-80] 24 00}  //weight: 1, accuracy: Low
        $x_1_2 = "[system.convert]::Frombase64string($" wide //weight: 1
        $x_1_3 = ".replace(" wide //weight: 1
        $x_1_4 = ";iex $" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

