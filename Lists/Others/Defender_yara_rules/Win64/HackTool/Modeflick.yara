rule HackTool_Win64_Modeflick_A_2147741909_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Modeflick.A"
        threat_id = "2147741909"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Modeflick"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "101"
        strings_accuracy = "High"
    strings:
        $x_50_1 = {48 89 5c 24 08 48 89 6c 24 10 57 48 83 ec 20 83}  //weight: 50, accuracy: High
        $x_50_2 = {48 8b 41 30 48 8b 49 38 48 ff 25}  //weight: 50, accuracy: High
        $x_50_3 = {48 8b 49 c8 48 8b 01 48 8b 40 08 48 ff 25}  //weight: 50, accuracy: High
        $x_1_4 = "IID_IEnumTfInputProcessorProfiles" wide //weight: 1
        $x_1_5 = "71C6E74D-0F28-11D8-A82A-00065B84435C" wide //weight: 1
        $x_1_6 = "IID_IEnumTfInputProcessorProfiles" ascii //weight: 1
        $x_1_7 = "71C6E74D-0F28-11D8-A82A-00065B84435C" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_50_*) and 1 of ($x_1_*))) or
            ((3 of ($x_50_*))) or
            (all of ($x*))
        )
}

