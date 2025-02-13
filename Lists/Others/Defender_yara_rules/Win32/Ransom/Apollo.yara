rule Ransom_Win32_Apollo_A_2147723888_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Apollo.A"
        threat_id = "2147723888"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Apollo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\Users\\sabri\\documents\\visual studio 2010\\Projects\\cripto\\Debug\\Stub.pdb" ascii //weight: 10
        $x_10_2 = "\\Users\\sabri\\documents\\visual studio 2010\\Projects\\cripto\\Release\\Stub.pdb" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Ransom_Win32_Apollo_A_2147723906_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Apollo.A!!Apollo.gen!A"
        threat_id = "2147723906"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Apollo"
        severity = "Critical"
        info = "Apollo: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "id=%s&pname=%s&uname=%s&pkey=%s&aekey=%s&ppub=%s&userx=%s" ascii //weight: 10
        $x_10_2 = "/stealer.php" ascii //weight: 10
        $x_10_3 = "url=%s&username=%s&password=%s" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

