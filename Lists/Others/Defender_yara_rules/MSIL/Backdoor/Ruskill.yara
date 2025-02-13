rule Backdoor_MSIL_Ruskill_ARK_2147849804_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Ruskill.ARK!MTB"
        threat_id = "2147849804"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ruskill"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 09 11 0a a3 3d 00 00 01 13 0b 00 11 0b 6f ?? ?? ?? 0a 00 00 11 0a 17 58 13 0a 11 0a 11 09 8e 69 32 dd}  //weight: 2, accuracy: Low
        $x_1_2 = "Added User/Pass ICARUS/ICARUS!" wide //weight: 1
        $x_1_3 = "Users\\ICARUS\\Desktop\\Google Chrome.lnk" wide //weight: 1
        $x_1_4 = "Users\\ICARUS\\Desktop\\Microsoft Edge.lnk" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

