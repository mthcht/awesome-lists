rule Ransom_Win32_Trasbind_A_2147645262_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Trasbind.A"
        threat_id = "2147645262"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Trasbind"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {05 a8 fd ff ff 99 6a 40 2b c2 68 58 02 00 00 d1 f8 68 20 03 00 00}  //weight: 5, accuracy: High
        $x_1_2 = "BFFF5675-ADC0-4740-81FF-7540597A0DC5" ascii //weight: 1
        $x_1_3 = "BFFF5675-ADC0-4740-81FF-7540597A0DC5" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

