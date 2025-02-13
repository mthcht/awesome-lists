rule Backdoor_Win32_Xifos_A_2147678381_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Xifos.A"
        threat_id = "2147678381"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Xifos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {74 68 65 71 75 69 63 6b 62 72 6f 77 6e 66 78 6a 6d 70 73 76 61 6c 7a 79 64 67 00}  //weight: 10, accuracy: High
        $x_1_2 = {78 78 78 78 78 3a 20 25 64 21 0a 00}  //weight: 1, accuracy: High
        $x_1_3 = {3e 20 6e 75 6c 00 00 2f 63 20 64 65 6c 20 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Xifos_C_2147679419_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Xifos.C"
        threat_id = "2147679419"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Xifos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "thequickbrownfxjmpsvalzydg" ascii //weight: 1
        $x_1_2 = "<PSM>Yep, %s is here.</PSM>" ascii //weight: 1
        $x_1_3 = "<MachineGuid>%s</MachineGuid>" ascii //weight: 1
        $x_1_4 = "johansson.scarlet@hotmail.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

