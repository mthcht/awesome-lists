rule Ransom_Win64_Obscura_A_2147957357_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Obscura.A"
        threat_id = "2147957357"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Obscura"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "failed to decode note: %s" ascii //weight: 1
        $x_1_2 = "peer public key wrong size" ascii //weight: 1
        $x_1_3 = "[+] detect standalone pc." ascii //weight: 1
        $x_1_4 = "[!!!] user not admin. exit [!!!]" ascii //weight: 1
        $x_1_5 = "README-OBSCURA.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

