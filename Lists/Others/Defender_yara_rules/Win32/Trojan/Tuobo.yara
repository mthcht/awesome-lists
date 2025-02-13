rule Trojan_Win32_Tuobo_A_2147599422_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tuobo.A"
        threat_id = "2147599422"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tuobo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = ".youtube.com/watch?v=" ascii //weight: 5
        $x_2_2 = {2f 66 6f 74 6f 73 2f [0-16] 2e 65 78 65}  //weight: 2, accuracy: Low
        $x_1_3 = "www.freewebtown.com" ascii //weight: 1
        $x_1_4 = "Configurada" ascii //weight: 1
        $x_5_5 = "YouTube Corporation. Todos os direitos" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

