rule TrojanSpy_Win32_Dold_A_2147657378_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Dold.A"
        threat_id = "2147657378"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Dold"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b7 fb 8b 55 00 0f b6 54 3a ff 0f b7 ce c1 e9 08 32 d1 88 54 38 ff 8b 04 24 0f b6 44 38 ff 66 03 f0 66 0f af 35 ?? ?? ?? ?? 66 03 35 ?? ?? ?? ?? 43 66 ff 4c 24 04 75 c0}  //weight: 10, accuracy: Low
        $x_10_2 = {0f 84 6c 01 00 00 2d cd ab cd ab 0f 84 a2 02 00 00 2d 33 54 32 54 0f 84 5b 02 00 00}  //weight: 10, accuracy: High
        $x_1_3 = "serasa.com.br" ascii //weight: 1
        $x_1_4 = "spc.org.br" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

