rule Ransom_Win32_EnignaCrypt_PAA_2147809333_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/EnignaCrypt.PAA!MTB"
        threat_id = "2147809333"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "EnignaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "torproject" ascii //weight: 1
        $x_1_2 = "enigma_info.txt" ascii //weight: 1
        $x_1_3 = "E_N_I_G_M_A.RSA" ascii //weight: 1
        $x_1_4 = "vssadmin delete shadows /all /quiet" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

