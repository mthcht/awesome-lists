rule HackTool_Win64_DirtyVanity_AMTB_2147964796_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/DirtyVanity!AMTB"
        threat_id = "2147964796"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "DirtyVanity"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Successfully wrote shellcode to victim. About to start the Mirroring" ascii //weight: 2
        $x_2_2 = "DirtyVanity [TARGET_PID_TO_REFLECT]" ascii //weight: 2
        $x_1_3 = "Dirty_Vanity.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

