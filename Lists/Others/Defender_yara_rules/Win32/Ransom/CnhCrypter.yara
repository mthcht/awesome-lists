rule Ransom_Win32_CnhCrypter_PA_2147773768_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/CnhCrypter.PA!MTB"
        threat_id = "2147773768"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "CnhCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "If you want back your files write to: helper.china@aol.com" ascii //weight: 1
        $x_1_2 = "README.txt" ascii //weight: 1
        $x_1_3 = "Local\\RustBacktraceMutex" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

