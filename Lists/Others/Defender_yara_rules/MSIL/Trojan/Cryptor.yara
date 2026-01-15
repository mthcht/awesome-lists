rule Trojan_MSIL_Cryptor_A_2147759285_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Cryptor.A!MTB"
        threat_id = "2147759285"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {11 00 19 8d 13 00 00 01 25 16 7e 04 00 00 04 a2 25 17 7e 05 00 00 04 a2 25 18 72 5b 00 00 70 a2 0a}  //weight: 3, accuracy: High
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "StartGame" wide //weight: 1
        $x_1_4 = {ef 00 bf 00 bd 00 20 00 55 00 70 00 64 00 61 00 74 00 65 00 20 00 52 00 6f 00 6f 00 6d 00}  //weight: 1, accuracy: High
        $x_1_5 = "ReverseStringDirect" ascii //weight: 1
        $x_1_6 = "Puzzle_Loader" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Cryptor_B_2147759686_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Cryptor.B!MTB"
        threat_id = "2147759686"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 02 0a 16 0b 38 f9 00 00 00 06 07 9a 0c 7e 57 00 00 0a 7e 10 00 00 04 08 28 36 00 00 06 73 53 00 00 0a 80 04 00 00 04 7e 12 00 00 04 08 7e 02 00 00 04 7e 11 00 00 04 28 3b 00 00 06 28 40 00 00 06 7e 02 00 00 04 73 50 00 00 0a 80 03 00 00 04 7e 13 00 00 04 7e 03 00 00 04 7e 04 00 00 04 19 20 08 18 02 00}  //weight: 1, accuracy: High
        $x_1_2 = "fdfrf.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Cryptor_LMB_2147961122_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Cryptor.LMB!MTB"
        threat_id = "2147961122"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {33 d2 48 8b c5 48 f7 f1 42 0f b6 44 22 07 30 04 2f 48 ff c5 49 3b ef}  //weight: 20, accuracy: High
        $x_5_2 = "GetRecoveryKey_BITLOCKER@@YA_NPEAXAEAV" ascii //weight: 5
        $x_3_3 = "CreateFile_BITLOCKER@@YAPEAXPEAUencrypt_source_opt@@PEAU_MYBD_KEYINFO@@PEAU_MYBD_PARAM@@@Z" ascii //weight: 3
        $x_2_4 = "ReadFile_BITLOCKER@@YA_NPEAX0IPEAI_K@Z" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

