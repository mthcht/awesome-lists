rule BrowserModifier_Win32_DeepSync_A_256238_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/DeepSync.A"
        threat_id = "256238"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "DeepSync"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\AppSync.pdb" ascii //weight: 1
        $x_1_2 = "do://updatefromtemp" wide //weight: 1
        $x_1_3 = "do://update?from=sched" wide //weight: 1
        $x_1_4 = "do://nextstage" wide //weight: 1
        $x_1_5 = "do://uninstall?guid=" wide //weight: 1
        $x_1_6 = "do://update?from=startup" wide //weight: 1
        $x_1_7 = "do://guard" wide //weight: 1
        $x_1_8 = "do://retake" wide //weight: 1
        $x_1_9 = "do://revive" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule BrowserModifier_Win32_DeepSync_B_256239_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/DeepSync.B"
        threat_id = "256239"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "DeepSync"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\AppMaster.pdb" ascii //weight: 1
        $x_1_2 = "force://install" wide //weight: 1
        $x_1_3 = "force://uninstall?guid=" wide //weight: 1
        $x_1_4 = "force://updatefromtemp?" wide //weight: 1
        $x_1_5 = "force://update?from=startup" wide //weight: 1
        $x_1_6 = "force://update?from=sched" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

