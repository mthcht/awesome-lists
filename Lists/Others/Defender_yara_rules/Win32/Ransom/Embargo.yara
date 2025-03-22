rule Ransom_Win32_Embargo_DA_2147912233_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Embargo.DA!MTB"
        threat_id = "2147912233"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Embargo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {65 00 6d 00 62 00 61 00 72 00 67 00 6f 00 3a 00 3a 00 [0-15] 3a 00 3a 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00}  //weight: 1, accuracy: Low
        $x_1_2 = {65 6d 62 61 72 67 6f 3a 3a [0-15] 3a 3a 65 6e 63 72 79 70 74}  //weight: 1, accuracy: Low
        $x_1_3 = "C:\\Windows\\System32\\cmd.exe/q/cbcdedit/set{default}recoveryenabledno" ascii //weight: 1
        $x_1_4 = "Deleted  shadows" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_Win32_Embargo_A_2147917637_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Embargo.A"
        threat_id = "2147917637"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Embargo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {f3 0f 6f 48 f0 f3 0f 6f 10 66 0f ef c8 66 0f ef d0 f3 0f 7f 48 f0 f3 0f 7f 10 83 c0 20 83 c6 e0 75 de}  //weight: 2, accuracy: High
        $x_2_2 = {65 6d 62 61 72 67 6f 3a 3a [0-48] 2f 65 6e 63 72 79 70 74 2e 72 73}  //weight: 2, accuracy: Low
        $x_1_3 = "bcdedit/set{default}recoveryenabledno" ascii //weight: 1
        $x_1_4 = "CryptConfigextensionnote_namepublic_keynote_contentsexclude_pathsfull_encrypt_extensions" ascii //weight: 1
        $x_1_5 = "kill_serviceskill_procsvm_extensionsexcluded_vmscredsprivate_key" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Embargo_B_2147917639_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Embargo.B"
        threat_id = "2147917639"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Embargo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\"note_contents\":\"Your network" ascii //weight: 2
        $x_2_2 = "\"note_name\":\"HOW_TO_RECOVER_FILES.txt\"" ascii //weight: 2
        $x_2_3 = "\"full_encrypt_extensions\":[\"" ascii //weight: 2
        $x_1_4 = "\"creds\":[\"police." ascii //weight: 1
        $x_1_5 = "\"exclude_paths\":[\"" ascii //weight: 1
        $x_1_6 = "\"excluded_vms\":[\"" ascii //weight: 1
        $x_1_7 = "\"kill_procs\":[\"" ascii //weight: 1
        $x_1_8 = "\"kill_services\":[\"" ascii //weight: 1
        $x_1_9 = "\"vm_extensions\":[\"*." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Embargo_GVA_2147936708_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Embargo.GVA!MTB"
        threat_id = "2147936708"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Embargo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "embargo::" ascii //weight: 1
        $x_3_2 = "logfileembargo" ascii //weight: 3
        $x_1_3 = "Failed selfdelete:" ascii //weight: 1
        $x_1_4 = "Deleted  shadows" ascii //weight: 1
        $x_2_5 = "embargo::winlib::encrypt" ascii //weight: 2
        $x_1_6 = "Failed to remove shadow:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

