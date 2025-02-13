rule Ransom_Win32_SanwaiCrypt_PA_2147793129_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/SanwaiCrypt.PA!MTB"
        threat_id = "2147793129"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "SanwaiCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".sanwai" ascii //weight: 1
        $x_1_2 = "your own risk" ascii //weight: 1
        $x_1_3 = "IMPORTANT.html" ascii //weight: 1
        $x_1_4 = "README!!!!.txt" ascii //weight: 1
        $x_1_5 = "\\gerjjkrkjjk33.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_Win32_SanwaiCrypt_PB_2147796154_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/SanwaiCrypt.PB!MTB"
        threat_id = "2147796154"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "SanwaiCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IMPORTANT.html" ascii //weight: 1
        $x_1_2 = "README!!!!.txt" ascii //weight: 1
        $x_3_3 = "\\gerjjkrkjjk33.pdb" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

