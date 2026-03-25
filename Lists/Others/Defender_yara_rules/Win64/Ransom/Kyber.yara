rule Ransom_Win64_Kyber_A_2147965498_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Kyber.A"
        threat_id = "2147965498"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Kyber"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Failed to open Service Control Manager" ascii //weight: 1
        $x_1_2 = "Failed to set value for file extension key:" ascii //weight: 1
        $x_1_3 = "Killing Microsoft Hyper-V machines.." ascii //weight: 1
        $x_1_4 = "Successfully encrypted" ascii //weight: 1
        $x_1_5 = "Error when trying to calc Kyber (ciphertext, shared_secret)" ascii //weight: 1
        $x_1_6 = "Error while creating note file:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

