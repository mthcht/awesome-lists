rule PWS_Win32_Yessim_2147605562_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Yessim"
        threat_id = "2147605562"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Yessim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\diskremovable" ascii //weight: 1
        $x_1_2 = "\\diskfixed" ascii //weight: 1
        $x_1_3 = "KeyLogger" ascii //weight: 1
        $x_2_4 = "[CMD][TRACK SITE]->" ascii //weight: 2
        $x_2_5 = "[KEYLOG RETRIEVER]->" ascii //weight: 2
        $x_5_6 = {73 69 6d 00 79 65 73 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

