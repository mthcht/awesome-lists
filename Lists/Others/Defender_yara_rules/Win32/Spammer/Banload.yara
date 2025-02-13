rule Spammer_Win32_Banload_A_2147615383_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Banload.A"
        threat_id = "2147615383"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AA_doMSNTimer" ascii //weight: 1
        $x_1_2 = "ListaMSNEnviar" ascii //weight: 1
        $x_1_3 = "AA_dataHTML1" ascii //weight: 1
        $x_1_4 = "C:\\Arquivos de programas\\msn_livers.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

