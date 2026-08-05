rule HackTool_MSIL_Screcwon_SN_2147975295_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/Screcwon.SN!MTB"
        threat_id = "2147975295"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Screcwon"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {28 47 00 00 0a 13 0f 11 0f 72 d2 03 00 70 6f 03 01 00 0a 13 10 11 10 28 04 01 00 0a 73 05 01 00 0a 13 11 11 11 6f 06 01 00 0a 13 12 08 28 0d 00 00 0a 2d 10 08 11 12 28 07 01 00 0a 16 13 1d dd 72 03 00 00 11 0b 2c 6f 11 05 1f 09 8d 33 00 00 01 13 22 11 22 16}  //weight: 5, accuracy: High
        $x_3_2 = "/qn /norestart\" -Wait -WindowStyle Hidden" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

