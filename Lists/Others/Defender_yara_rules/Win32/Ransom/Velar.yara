rule Ransom_Win32_Velar_PA_2147752071_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Velar.PA!MTB"
        threat_id = "2147752071"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Velar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "a large number of your files has been encrypted using a hybrid encryption scheme" wide //weight: 1
        $x_1_2 = ".Velar" wide //weight: 1
        $x_1_3 = "subject: ID-{KEY11111}" wide //weight: 1
        $x_1_4 = "There is no possibility to decrypt these files without a special decrypt program" wide //weight: 1
        $x_1_5 = {2e 00 73 00 63 00 72 00 [0-4] 2e 00 63 00 6d 00 64 00 [0-4] 2e 00 64 00 6c 00 6c 00 [0-4] 2e 00 62 00 61 00 74 00 [0-4] 2e 00 63 00 70 00 6c 00 [0-4] 2e 00 73 00 79 00 73 00 [0-4] 2e 00 6d 00 73 00 63 00 [0-4] 2e 00 63 00 6f 00 6d 00 [0-4] 2e 00 6c 00 6e 00 6b 00 [0-4] 2e 00 6d 00 73 00 70 00 [0-4] 2e 00 70 00 69 00 66 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

