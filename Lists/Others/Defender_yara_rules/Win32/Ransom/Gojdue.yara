rule Ransom_Win32_Gojdue_A_2147720976_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Gojdue.A"
        threat_id = "2147720976"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Gojdue"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Desktop\\HOW_TO_DECRYPT_FILES.html" ascii //weight: 1
        $x_1_2 = ".onion.to/decrypt/" ascii //weight: 1
        $x_1_3 = "<p>To decrypt your files" ascii //weight: 1
        $x_1_4 = "Go build ID" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

