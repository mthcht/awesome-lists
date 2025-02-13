rule Trojan_Win32_Feibiut_A_2147718066_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Feibiut.A"
        threat_id = "2147718066"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Feibiut"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 50 4f 4c 44 00}  //weight: 1, accuracy: High
        $x_1_2 = "%s\\~%d.exe" ascii //weight: 1
        $x_1_3 = "dGFzay5kbnMtc3luLmNvbQ==" ascii //weight: 1
        $x_1_4 = "/config?t=%I64d&v=%d" ascii //weight: 1
        $x_1_5 = "\\Microsoft Shared\\Triedit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

