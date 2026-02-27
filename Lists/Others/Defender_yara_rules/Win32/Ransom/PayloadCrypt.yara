rule Ransom_Win32_PayloadCrypt_PA_2147963705_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/PayloadCrypt.PA!MTB"
        threat_id = "2147963705"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "PayloadCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "\\payload.log" wide //weight: 3
        $x_1_2 = "RECOVER_payload.txt" ascii //weight: 1
        $x_1_3 = "/c vssadmin.exe delete shadows /all /quiet" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

