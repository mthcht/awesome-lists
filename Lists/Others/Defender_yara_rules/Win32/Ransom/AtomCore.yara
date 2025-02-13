rule Ransom_Win32_AtomCore_DA_2147772922_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/AtomCore.DA!MTB"
        threat_id = "2147772922"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "AtomCore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "decryption_price" ascii //weight: 1
        $x_1_2 = "bitcoin_user_address" ascii //weight: 1
        $x_1_3 = "|*.pdf" ascii //weight: 1
        $x_1_4 = "tracking_id" ascii //weight: 1
        $x_1_5 = "atom_core" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

