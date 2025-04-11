rule Ransom_Win32_Xiaoba_YAC_2147938648_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Xiaoba.YAC!MTB"
        threat_id = "2147938648"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Xiaoba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SAPI.Speak" ascii //weight: 1
        $x_1_2 = "files have been encrypted" ascii //weight: 1
        $x_1_3 = "Attention! Attention!" ascii //weight: 1
        $x_1_4 = "HELP_SOS" ascii //weight: 1
        $x_1_5 = "vssadmin delete shadow" ascii //weight: 1
        $x_10_6 = "XIAOBA 2.0 Ransomware" ascii //weight: 10
        $x_1_7 = "setelah menyelesaikan transaksi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

