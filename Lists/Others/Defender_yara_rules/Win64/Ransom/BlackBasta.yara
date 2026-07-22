rule Ransom_Win64_BlackBasta_NUA_2147964431_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/BlackBasta.NUA!MTB"
        threat_id = "2147964431"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "BlackBasta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "You can contact us and decrypt one file" ascii //weight: 1
        $x_1_2 = "zYcbRL1aoef4gbbhOXPvKl4PmKX7rbdGXL" ascii //weight: 1
        $x_1_3 = "Your data are stolen and encrypted" ascii //weight: 1
        $x_1_4 = "Done time: %.4f seconds, encrypted: %.4f gb" ascii //weight: 1
        $x_2_5 = "C:\\Windows\\SysNative\\vssadmin.exe delete shadows /all /quiet" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_BlackBasta_NYD_2147974300_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/BlackBasta.NYD!MTB"
        threat_id = "2147974300"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "BlackBasta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "P1loYXUx1wZM1ooXbnfs1xSKF3JvcYp" ascii //weight: 2
        $x_1_2 = "E5fS1qJhd2R5aSA2yFdadX+I1Gn1LHz3MZH+R9MTCer8BBvnkrEg/tggKWyv9R4B" ascii //weight: 1
        $x_1_3 = "4+zbkSxTYA2V9miQxlgzJA5DZtnMG394wZhtQ4BevRDuXJmJGwqiRNl4rpUxsEal" ascii //weight: 1
        $x_1_4 = "EiTJfEv+WOGiq+YjVAoW8cjTWVp66BNQ0rMxAcbR1tyccsW1xpNy7yMo+8VHQZ1Q" ascii //weight: 1
        $x_1_5 = "hybJ4oU1Ef/zWyZWbrbSufNSEKk7pEuyAkPRaPl7mNG3caYLcfhKdLYEGaeNYP4f" ascii //weight: 1
        $x_1_6 = "cr+M7asBYENqWTbVktiOUmDD1FuZYUTwi2xUiau/mZOmEErWEKC+fNHtMcXreHP9" ascii //weight: 1
        $x_1_7 = "106Arq9dEj4wvGShF/wSk2doRjFEg4wHFXI839lTE01JNXzRm24PvN6mwAfV4oap" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

