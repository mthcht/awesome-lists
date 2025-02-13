rule Ransom_Win32_GopherCrypt_PA_2147777548_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/GopherCrypt.PA!MTB"
        threat_id = "2147777548"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "GopherCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Delete Shadows /All /Quiet" ascii //weight: 1
        $x_1_2 = "delete catalog - quiet" ascii //weight: 1
        $x_1_3 = ".gopher" ascii //weight: 1
        $x_1_4 = "You have been infected by the Bad Gopher virus" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

