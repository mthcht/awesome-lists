rule Ransom_Win64_KilladaCrypt_PA_2147967072_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/KilladaCrypt.PA!MTB"
        threat_id = "2147967072"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "KilladaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "killada.pdb" ascii //weight: 3
        $x_1_2 = "cmd.exe /e:ON /v:OFF /d /c" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

