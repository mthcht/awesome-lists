rule Ransom_Win64_Braincrypt_A_2147719880_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Braincrypt.A"
        threat_id = "2147719880"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Braincrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "braincrypt.go" ascii //weight: 1
        $x_1_2 = "/gateway/gate.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

