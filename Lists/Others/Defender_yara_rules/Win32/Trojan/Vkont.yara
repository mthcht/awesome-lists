rule Trojan_Win32_Vkont_C_2147652518_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vkont.C"
        threat_id = "2147652518"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vkont"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\hosts\\release\\hosts.pdb" ascii //weight: 1
        $x_1_2 = "DATA: %x %x %x %x %x %x!" ascii //weight: 1
        $x_1_3 = {0f 84 a4 00 00 00 8b ?? ?? 0f ?? ?? ?? ?? 81 fa cc 00 00 00 0f 84 90 00 00 00 8b ?? ?? 8b 88 0c 02 00 00 8b ?? ?? c6 04 11 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

