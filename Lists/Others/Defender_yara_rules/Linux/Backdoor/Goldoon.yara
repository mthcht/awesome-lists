rule Backdoor_Linux_Goldoon_A_2147910683_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Goldoon.A!MTB"
        threat_id = "2147910683"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Goldoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 38 35 2e 31 30 36 2e 39 34 2e 35 31 00 [0-16] 6c 69 6e 75 78}  //weight: 1, accuracy: Low
        $x_1_2 = {63 68 6d 6f 64 00 65 78 65 63 76 70 00 [0-16] 5f}  //weight: 1, accuracy: Low
        $x_1_3 = "User-Agent: FBI-Agent (Checking You)" ascii //weight: 1
        $x_1_4 = "YesItsAnAntiHoneypotBaby" ascii //weight: 1
        $x_1_5 = "yesItsSusybaby" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

