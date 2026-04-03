rule Ransom_Win32_EXITIUM_YBF_2147966293_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/EXITIUM.YBF!MTB"
        threat_id = "2147966293"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "EXITIUM"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "YOU ARE UNDER ATTACK" wide //weight: 5
        $x_5_2 = "RunPayload.bat" ascii //weight: 5
        $x_1_3 = "Exitium ransomware" ascii //weight: 1
        $x_1_4 = "infra have been encrypted" ascii //weight: 1
        $x_1_5 = "files was fetched and encrypted" ascii //weight: 1
        $x_1_6 = "Ransom.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

