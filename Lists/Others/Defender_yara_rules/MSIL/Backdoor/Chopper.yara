rule Backdoor_MSIL_Chopper_EX_2147776870_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Chopper.EX!dha"
        threat_id = "2147776870"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Chopper"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "~/auth/Current/themes/resources/resources.aspx" wide //weight: 1
        $x_1_2 = "function xor(rawStr:String,key:String):String{" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Chopper_C_2147832691_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Chopper.C"
        threat_id = "2147832691"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Chopper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {28 15 00 00 0a 28 16 00 00 0a 25 72 ?? ?? ?? ?? 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 25 72 ?? ?? ?? ?? 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 25 72 ?? ?? ?? ?? 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 0a 02}  //weight: 1, accuracy: Low
        $x_1_2 = "App_Web_" ascii //weight: 1
        $x_1_3 = "%65%76%61%6c%28%52" wide //weight: 1
        $x_1_4 = {25 00 37 00 34 00 25 00 35 00 62 00 25 00 32 00 32 00 [0-64] 25 00 32 00 32 00 25 00 35 00 64 00 25 00 32 00 39 00 25 00 33 00 62 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Chopper_AOP_2147847541_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Chopper.AOP!MTB"
        threat_id = "2147847541"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Chopper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0a 25 16 9a 74 13 00 00 01 fe 0b 01 00 25 17 9a 74 14 00 00 01 fe 0b 02 00 25 18 9a 0a 26 02 6f 12 00 00 0a 28 18 00 00 0a 74 1b 00 00 01 7b 19 00 00 0a 25 16 03 a2 25 17 04 a2 25 18 06 a2 26}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

