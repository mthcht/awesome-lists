rule Ransom_Win32_Hardbit_PA_2147837680_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Hardbit.PA!MTB"
        threat_id = "2147837680"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Hardbit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "All your files have been stolen and then encrypted" ascii //weight: 1
        $x_1_2 = "until the last file is decrypted" ascii //weight: 1
        $x_1_3 = "cyber insurance against ransomware attacks" ascii //weight: 1
        $x_1_4 = "guarantee to restore files" ascii //weight: 1
        $x_1_5 = "pay us via Bitcoin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

