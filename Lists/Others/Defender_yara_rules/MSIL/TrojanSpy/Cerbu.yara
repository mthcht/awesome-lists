rule TrojanSpy_MSIL_Cerbu_ARA_2147970344_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Cerbu.ARA!MTB"
        threat_id = "2147970344"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cerbu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 06 02 07 91 7e ?? ?? ?? 04 07 7e ?? ?? ?? 04 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 61 d2 6f ?? ?? ?? 0a 00 00 07 17 58 0b 07 02 8e 69 fe 04 0c 08 2d ce}  //weight: 2, accuracy: Low
        $x_2_2 = "/v3/upload?uuid={0}&index={1}&parent={2}&uploadKey={3}&hash={4}" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

