rule Trojan_Win64_Insont_A_2147727586_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Insont.A"
        threat_id = "2147727586"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Insont"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 49 6e 74 65 72 6e 65 74 20 53 65 74 74 69 6e 67 73 5c 5a 6f 6e 65 73 5c 33 00 32 35 30 30}  //weight: 1, accuracy: High
        $x_1_2 = "http://212.109.196.67/gateway.php" ascii //weight: 1
        $x_1_3 = "\"inject\": \"<script>var home_link = \\\"https" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

