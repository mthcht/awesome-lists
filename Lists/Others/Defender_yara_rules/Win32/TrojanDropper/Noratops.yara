rule TrojanDropper_Win32_Noratops_A_2147693816_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Noratops.A!dha"
        threat_id = "2147693816"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Noratops"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s~$st%d%d%d.%s" wide //weight: 1
        $x_1_2 = "/general.png" wide //weight: 1
        $x_1_3 = "\"%s\",_dec" wide //weight: 1
        $x_1_4 = "/n%d.png" wide //weight: 1
        $x_1_5 = "rundll32.exe" wide //weight: 1
        $x_1_6 = "unknown compression method" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Noratops_A_2147693816_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Noratops.A!dha"
        threat_id = "2147693816"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Noratops"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "get_CTITF_formmmm" ascii //weight: 1
        $x_1_2 = ".tmp,_dec" wide //weight: 1
        $x_1_3 = "/c rundll32 ~$" wide //weight: 1
        $x_1_4 = "\\CTITF form.pdf" wide //weight: 1
        $x_1_5 = "%PDF-1." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Noratops_B_2147723364_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Noratops.B!dha"
        threat_id = "2147723364"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Noratops"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e3 06 03 df 8b bd e8 fd ff ff c1 e3 06 03 d8 3b ?? 73 4c}  //weight: 1, accuracy: Low
        $x_1_2 = "ReflectiveLoader" ascii //weight: 1
        $x_1_3 = "Injector.dll" ascii //weight: 1
        $x_1_4 = "_dec" ascii //weight: 1
        $x_1_5 = "__dec" ascii //weight: 1
        $x_1_6 = {56 00 25 00 64 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = "INFO" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

