rule Ransom_Win32_Ysakrypt_A_2147721563_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Ysakrypt.A"
        threat_id = "2147721563"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Ysakrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "2747863794C5562716774766F635C555" ascii //weight: 1
        $x_1_2 = "EXECUTE ( BINARYTOSTRING ( STRINGREVERSE ( STRINGREPLACE (" ascii //weight: 1
        $x_1_3 = "42829756B4566796275644F54707972734F5" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

