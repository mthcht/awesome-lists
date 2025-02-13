rule Ransom_Win64_Vovalex_MK_2147772926_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Vovalex.MK!MTB"
        threat_id = "2147772926"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Vovalex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vovalex" ascii //weight: 1
        $x_1_2 = "README.VOVALEX.txt" ascii //weight: 1
        $x_1_3 = "phobos" ascii //weight: 1
        $x_1_4 = "Your photos, documents and other files have been encrypted" ascii //weight: 1
        $x_1_5 = "The decryptor costs 0.5 XMR" ascii //weight: 1
        $x_1_6 = "@cock.li" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

