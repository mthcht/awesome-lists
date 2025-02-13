rule Trojan_Win64_Sminager_AA_2147920526_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sminager.AA!MTB"
        threat_id = "2147920526"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sminager"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {50 61 74 68 3d 25 41 50 50 44 41 54 41 25 2f 53 65 74 70 6f 6f 6c 0d 0a 53 65 74 75 70 3d 41 50 50 2e 76 62 73 0d 0a 53 69 6c 65 6e 74 3d 32}  //weight: 10, accuracy: High
        $x_10_2 = "you agree to use the resources of your PC (CPU and / or graphics card load is possible from 5% to 100%)" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

