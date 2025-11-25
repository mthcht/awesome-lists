rule Backdoor_Win64_Remcos_GTD_2147958171_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Remcos.GTD!MTB"
        threat_id = "2147958171"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {ac f8 ac 00 ad ?? ?? ?? ?? 18 ad ?? ?? ?? ?? 30 ad ?? ?? ?? ?? 48 ad 50 ad 58 ad 00 10 07 00 30 00 00 00 20}  //weight: 10, accuracy: Low
        $x_1_2 = "\\RAT\\Backdoor\\Release\\Backdoor.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

