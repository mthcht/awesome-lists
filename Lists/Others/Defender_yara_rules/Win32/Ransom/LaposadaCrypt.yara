rule Ransom_Win32_LaposadaCrypt_PAA_2147809504_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LaposadaCrypt.PAA!MTB"
        threat_id = "2147809504"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LaposadaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".laposada-" ascii //weight: 1
        $x_1_2 = "--kill-susp" ascii //weight: 1
        $x_1_3 = "EncryptionStage" ascii //weight: 1
        $x_1_4 = "recover all your files." ascii //weight: 1
        $x_1_5 = "network was compromised." ascii //weight: 1
        $x_1_6 = "!!laposada_howtodecipher.inf" ascii //weight: 1
        $x_1_7 = "! cynet ransom protection(don't delete)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

