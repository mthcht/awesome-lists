rule HackTool_Win32_Binder_B_2147621796_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Binder.B"
        threat_id = "2147621796"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Binder"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Settings - Binder |by Permabatt" ascii //weight: 1
        $x_1_2 = "\\Stub\\Stub.exe" wide //weight: 1
        $x_1_3 = "If you want the binder to use another stub-file than the usual one, choose your stub-file here !" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

