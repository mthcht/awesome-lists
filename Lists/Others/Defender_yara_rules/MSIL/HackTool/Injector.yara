rule HackTool_MSIL_Injector_2147653802_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/Injector"
        threat_id = "2147653802"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Tools\\VAC\\BypassLLI.dll" ascii //weight: 1
        $x_1_2 = "Press enter, and the hook will be done!" ascii //weight: 1
        $x_1_3 = "000webhostapp.com" wide //weight: 1
        $x_1_4 = "Launching Process, Start Method" ascii //weight: 1
        $x_1_5 = "Injecting, Please Wait" ascii //weight: 1
        $x_1_6 = "Do you want to Bypass LoadLibrary" ascii //weight: 1
        $x_1_7 = "Running VAC Bypass, Please Wait" ascii //weight: 1
        $x_1_8 = "Starting Injection" ascii //weight: 1
        $x_1_9 = "Starting Engine: DIH Engine" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_MSIL_Injector_A_2147707926_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/Injector.A"
        threat_id = "2147707926"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 08 07 8e 69 5d 91 08 06 58 07 8e 69 58 1f 1f 5f 63 20 ff 00 00 00 5f d2 61 d2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_MSIL_Injector_B_2147710059_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/Injector.B!bit"
        threat_id = "2147710059"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "High"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "=IzMsVmbyV2a" wide //weight: 1
        $x_1_2 = "=c1czV2YvJHUlRXYlJ3Q" wide //weight: 1
        $x_1_3 = "=wGbkRnb" wide //weight: 1
        $x_1_4 = "=42bpR3YlNlZPdXZpZFch1mbVRnT" wide //weight: 1
        $x_1_5 = "==Ad4VGdu92QkFWZyhGV0V2R" wide //weight: 1
        $x_1_6 = "==AeFR3YlR3byBFbhVHdylmV" wide //weight: 1
        $x_1_7 = "5J3btVWTzNXZj9mcQVGdpJ3V" wide //weight: 1
        $x_1_8 = "==Ad4VGdu92QkFWZyhGV0V2U" wide //weight: 1
        $x_1_9 = "kFWZyhGVl1WdzVmU" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

