rule Backdoor_Win64_Donipye_STX_2147781287_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Donipye.STX"
        threat_id = "2147781287"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Donipye"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "dllmodule.6.dll" ascii //weight: 1
        $x_1_2 = {2f 00 62 00 2e 00 70 00 68 00 70 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {67 00 65 00 74 00 74 00 69 00 6e 00 67 00 20 00 67 00 72 00 6f 00 75 00 70 00 73 00 [0-96] 53 00 2d 00 31 00 2d 00 35 00 2d 00 33 00 32 00 2d 00 35 00 34 00 34 00}  //weight: 1, accuracy: Low
        $x_2_4 = ".xyz/ssh.zip" wide //weight: 2
        $x_2_5 = "WbemScripting.SWbemLocator" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

