rule Ransom_Win32_Crylock_PAA_2147785418_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Crylock.PAA!MTB"
        threat_id = "2147785418"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Crylock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "///END PROCESSES WHITE LIST\\\\\\" ascii //weight: 1
        $x_1_2 = "///END UNENCRYPT FILES LIST\\\\\\" ascii //weight: 1
        $x_1_3 = "/c \"ping 0.0.0.0&del \"" ascii //weight: 1
        $x_1_4 = "how_to_decrypt.hta" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

