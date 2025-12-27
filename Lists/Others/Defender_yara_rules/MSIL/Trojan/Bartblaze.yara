rule Trojan_MSIL_Bartblaze_MCP_2147958530_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bartblaze.MCP!MTB"
        threat_id = "2147958530"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bartblaze"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 38 31 36 33 39 38 39 2e 65 78 65 00 3c 4d 6f 64 75 6c 65 3e 00 50 6f 6c 69 63 79 00 32 38 30 33 32 30 32 33 31 39 36 31 39 4a 4b 47 46 4b 5a 41 46 48 4b 49 4b 48 46 5a 48 44 54 4b 47 48 41 47 5a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

