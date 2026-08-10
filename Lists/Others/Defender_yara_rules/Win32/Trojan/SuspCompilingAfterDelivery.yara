rule Trojan_Win32_SuspCompilingAfterDelivery_MK_2147975822_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspCompilingAfterDelivery.MK"
        threat_id = "2147975822"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspCompilingAfterDelivery"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vbc.exe" wide //weight: 1
        $x_1_2 = "jsc.exe" wide //weight: 1
        $x_1_3 = "ilasm.exe" wide //weight: 1
        $x_1_4 = "msxsl.exe" wide //weight: 1
        $n_1_5 = "8fd1d7cc-74b7-4610-836b-4c1f01ba7b72" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

