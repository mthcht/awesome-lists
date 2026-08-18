rule Ransom_Win32_Majin_YAUA_2147976390_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Majin.YAUA!MTB"
        threat_id = "2147976390"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Majin"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Global\\majinahanashi_Mutex" ascii //weight: 3
        $x_3_2 = "majinahanashi" ascii //weight: 3
        $x_3_3 = "ENCRYPTEDAES256!SCT2" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

