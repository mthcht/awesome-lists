rule Ransom_Win32_Zorba_AA_2147756267_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Zorba.AA!MTB"
        threat_id = "2147756267"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Zorba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= ZORAB =" ascii //weight: 1
        $x_1_2 = "Your documents, photos, databases and other important files are encrypted and have the extension: .ZRB" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

