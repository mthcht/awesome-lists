rule HackTool_Win32_AmsiETWPatch_SN_2147968912_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/AmsiETWPatch.SN!MTB"
        threat_id = "2147968912"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "AmsiETWPatch"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Your computer has been attacked by Cabbit Lock" wide //weight: 2
        $x_2_2 = "There's no way out! The BIOS will be deleted if you try to escape" wide //weight: 2
        $x_2_3 = "CABBIT GOD" wide //weight: 2
        $x_2_4 = "YOUR_FILES_ENCRYPTED.txt" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

