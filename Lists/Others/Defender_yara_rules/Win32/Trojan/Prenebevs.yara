rule Trojan_Win32_Prenebevs_A_2147723729_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Prenebevs.A!!Prenebevs.gen!A"
        threat_id = "2147723729"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Prenebevs"
        severity = "Critical"
        info = "Prenebevs: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {31 ff 31 c0 ac c1 cf 0d 01 c7 38 e0 75 f4 03 7d f8}  //weight: 10, accuracy: High
        $x_10_2 = {89 44 24 24 5b 5b 61 59 5a 51 ff e0}  //weight: 10, accuracy: High
        $x_10_3 = "Mozilla/5.0 (Wind" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

