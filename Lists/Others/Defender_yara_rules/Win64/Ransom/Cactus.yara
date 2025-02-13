rule Ransom_Win64_Cactus_PB_2147846650_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Cactus.PB!MTB"
        threat_id = "2147846650"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Cactus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "cAcTuS.readme.txt" wide //weight: 4
        $x_1_2 = "accessed and encrypted by" wide //weight: 1
        $x_1_3 = "b4kr-xr7h-qcps-omu3" wide //weight: 1
        $x_1_4 = "schtasks.exe /create /sc MINUTE /mo 5 /rl HIGHEST" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

