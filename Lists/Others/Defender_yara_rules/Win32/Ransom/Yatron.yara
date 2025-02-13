rule Ransom_Win32_Yatron_SA_2147734193_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Yatron.SA"
        threat_id = "2147734193"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Yatron"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "stub j2.exe" ascii //weight: 1
        $x_1_2 = "c_AntiKill" ascii //weight: 1
        $x_1_3 = "EncryptFile" ascii //weight: 1
        $x_1_4 = "Fuck_all" ascii //weight: 1
        $x_1_5 = "Yatron" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

