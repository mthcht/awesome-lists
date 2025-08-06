rule HackTool_MacOS_ShellcodeInject_B_2147948590_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/ShellcodeInject.B"
        threat_id = "2147948590"
        type = "HackTool"
        platform = "MacOS: "
        family = "ShellcodeInject"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {21 0c 8e d2 01 0e a0 f2 e1 83 1f f8 61 ac 8e d2 81 2d ac f2 81 ee cd f2 41 ce e5 f2 e1 03 1f f8 21 ed 8d d2 c1 6d ae f2 e1 65}  //weight: 1, accuracy: High
        $x_1_2 = {c8 f2 21 8c ed f2 e1 83 1e f8 21 08 8e d2 01 8e ad f2 21 6d cc f2 21 8c ee f2 e1 03 1e f8 e1 65 8a d2 21 6f ae f2 81 ae cc f2}  //weight: 1, accuracy: High
        $x_1_3 = {a1 ed e5 f2 e1 83 1d f8 e1 e5 8d d2 01 ae ac f2 c1 0d c0 f2 e1 03 1d f8 e1 a5 8e d2 61 4e ae f2 e1 45 cc f2 21 cd ed f2 e1 83}  //weight: 1, accuracy: High
        $x_1_4 = {1c f8 ff 03 1c f8 01 05 80 d2 e1 63 21 cb e1 83 1b f8 01 07 80 d2 e1 63 21 cb e1 03 1b f8 e0 03 01 aa e1 43 01 d1 e2 03 1f aa 70 07 80 d2 e1 66 02 d4}  //weight: 1, accuracy: High
        $x_1_5 = "_vm_protect" ascii //weight: 1
        $x_1_6 = "_mach_vm_allocate" ascii //weight: 1
        $x_1_7 = "_mach_vm_write" ascii //weight: 1
        $x_1_8 = "_thread_create_running" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

