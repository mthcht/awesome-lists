rule Ransom_Win32_MatrixCrypt_PA_2147813365_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/MatrixCrypt.PA!MTB"
        threat_id = "2147813365"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "MatrixCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 c9 fd 43 03 00 81 c1 c3 9e 26 00 8b d1 c1 ea 10 30 14 06 8b 55 ?? 40 3b c2 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

