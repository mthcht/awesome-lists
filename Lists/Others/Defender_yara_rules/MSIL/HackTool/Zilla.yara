rule HackTool_MSIL_Zilla_NZ_2147937541_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/Zilla.NZ!MTB"
        threat_id = "2147937541"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zilla"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {7e 04 00 00 04 7b 04 01 00 04 6f 20 01 00 06 11 04 6f 42 00 00 0a 00 11 04 28 3c 00 00 0a 26 73 43 00 00 0a 25 72 c7 00 00 70 28 3f 00 00 0a 72 0f 01 00 70 28 40 00 00 0a 6f 44 00 00 0a 00 25 17 6f 45 00 00 0a 00 25 17 6f 46 00 00 0a 00 25 72 13 01 00 70}  //weight: 2, accuracy: High
        $x_1_2 = "You're connecting too fast to loader, slow down" wide //weight: 1
        $x_1_3 = "Let's Encrypt" wide //weight: 1
        $x_1_4 = "syllec.xyz" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

