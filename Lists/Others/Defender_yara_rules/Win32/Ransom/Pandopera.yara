rule Ransom_Win32_Pandopera_2147772190_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Pandopera!MSR"
        threat_id = "2147772190"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Pandopera"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\TEMP\\Panda\\sppser.exe" ascii //weight: 1
        $x_1_2 = "C:\\TEMP\\Panda\\\\*.sft" wide //weight: 1
        $x_1_3 = "winmsism.exe" wide //weight: 1
        $x_1_4 = "https://hostoperationsystems.com" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

