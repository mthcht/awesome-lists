rule Ransom_Win32_PsychoCrypt_PA_2147806023_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/PsychoCrypt.PA!MTB"
        threat_id = "2147806023"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "PsychoCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Read_Me!_.txt" wide //weight: 1
        $x_1_2 = "\\Desktop\\ReadMe_Now!.hta" wide //weight: 1
        $x_1_3 = "vssadmin.exe Delete Shadows /All /Quiet" ascii //weight: 1
        $x_1_4 = "Your Data Locked" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

