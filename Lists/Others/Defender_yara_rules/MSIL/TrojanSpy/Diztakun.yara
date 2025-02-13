rule TrojanSpy_MSIL_Diztakun_SK_2147925364_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Diztakun.SK!MTB"
        threat_id = "2147925364"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Diztakun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 06 07 8e 69 6f 09 00 00 0a 8f 06 00 00 01 28 0a 00 00 0a 0c 09 08 28 0b 00 00 0a 0d 11 04 17 58 13 04 11 04 02 32 d8}  //weight: 2, accuracy: High
        $x_1_2 = "888\\obj\\Release\\888.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

