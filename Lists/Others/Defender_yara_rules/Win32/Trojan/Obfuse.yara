rule Trojan_Win32_Obfuse_RA_2147755588_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuse.RA!MTB"
        threat_id = "2147755588"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "YNoEf1Xw9XsoEh9yKDpUpBSFWRO210" wide //weight: 1
        $x_1_2 = "F6HltzMSRMheozYeu118" wide //weight: 1
        $x_1_3 = "KTMPoOK3LSa6Om4z6E63b62" wide //weight: 1
        $x_1_4 = "cwL40M8H1dBiyZpDuukYuLW7ms8YIQRfNdbj246" wide //weight: 1
        $x_1_5 = "gsTyRrSXOpRGQVBMRc6vbZ25" wide //weight: 1
        $x_1_6 = "Q8aeHLTrd6yMuBi9XQVm82qTLLzE231" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Obfuse_PR_2147933953_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuse.PR!AMTB"
        threat_id = "2147933953"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuse"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Form2_Load" ascii //weight: 1
        $x_1_2 = "remoQccount" ascii //weight: 1
        $x_1_3 = "Replace" ascii //weight: 1
        $x_1_4 = "DIRERNIF" ascii //weight: 1
        $x_1_5 = "get_appiath" ascii //weight: 1
        $x_1_6 = "downQdata" ascii //weight: 1
        $x_1_7 = "loadQdata" ascii //weight: 1
        $x_1_8 = "$44aa0e8d-a493-473c-9aff-f5a8219dff5f" ascii //weight: 1
        $x_1_9 = "e:\\ivdvmrs vido\\ivdvmrs vido\\obj\\Debug\\ivdvmrs vido.pdb" ascii //weight: 1
        $x_1_10 = "SOF_TWA_RE\\Mic_ro_soft\\Win_dows\\Cur_rent_Vers_ion\\_Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuse_PR_2147933953_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuse.PR!AMTB"
        threat_id = "2147933953"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuse"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DIRSNIF" ascii //weight: 1
        $x_1_2 = "get_appiath" ascii //weight: 1
        $x_1_3 = "Form1_Load" ascii //weight: 1
        $x_1_4 = "remoQccount" ascii //weight: 1
        $x_1_5 = "downQdata" ascii //weight: 1
        $x_1_6 = "loadQdata" ascii //weight: 1
        $x_1_7 = "Replace" ascii //weight: 1
        $x_1_8 = "Split" ascii //weight: 1
        $x_1_9 = "WriteAllBytes" ascii //weight: 1
        $x_1_10 = "$068946cb-0306-47cd-b8c9-95c879d4f143" ascii //weight: 1
        $x_1_11 = "e:\\wqeex\\jedvmtrvh\\jedvmtrvh\\obj\\Debug\\jedvmtrvh.pdb" ascii //weight: 1
        $x_1_12 = "SOF_TWA_RE\\Mic_rosoft\\Win_dows\\Current_Version\\_Run" ascii //weight: 1
        $x_1_13 = ".exe|" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuse_A_2147946016_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuse.A"
        threat_id = "2147946016"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 45 d4 6b 65 72 6e c7 45 d8 65 6c 33 32 c7 45 dc 2e 64 6c 6c c6 45 e0 00}  //weight: 1, accuracy: High
        $x_1_2 = {c7 45 e4 47 65 74 54 c7 45 e8 69 63 6b 43 c7 45 ec 6f 75 6e 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

