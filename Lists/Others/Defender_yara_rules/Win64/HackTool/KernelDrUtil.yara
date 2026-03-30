rule HackTool_Win64_KernelDrUtil_P_2147965876_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/KernelDrUtil.P!MTB"
        threat_id = "2147965876"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "KernelDrUtil"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[!] Cannot query victim driver information" ascii //weight: 1
        $x_1_2 = "[!] Cannot query victim driver layout" ascii //weight: 1
        $x_1_3 = "[!] Could not extract victim driver, abort" ascii //weight: 1
        $x_1_4 = "[!] Error preloading victim driver, abort" ascii //weight: 1
        $x_1_5 = "[!] Error writing shellcode to the target driver, abort" ascii //weight: 1
        $x_1_6 = "[!] Victim driver already loaded, force reload" ascii //weight: 1
        $x_1_7 = "[+] Executing shellcode" ascii //weight: 1
        $x_1_8 = "[+] Extracting victim driver \"%ws\" as \"%ws\"" ascii //weight: 1
        $x_1_9 = "[+] Previous instance of victim driver unloaded" ascii //weight: 1
        $x_1_10 = "[+] Processing victim \"%ws\" driver" ascii //weight: 1
        $x_1_11 = "[+] Query victim loaded driver layout" ascii //weight: 1
        $x_1_12 = "[+] Successfully loaded victim driver" ascii //weight: 1
        $x_10_13 = "\\Hamakaze\\output\\x64\\Release\\kdu.pdb" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((11 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

