rule Ransom_Win32_Amrakdow_A_2147786280_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Amrakdow.A"
        threat_id = "2147786280"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Amrakdow"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@onionmail.org" ascii //weight: 1
        $x_1_2 = "Your network has been breached by Karma ransomware group" ascii //weight: 1
        $x_1_3 = "aaa_TouchMeNot_.txt" wide //weight: 1
        $x_1_4 = "KARMA-AGREE.t" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_Win32_Amrakdow_B_2147793950_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Amrakdow.B"
        threat_id = "2147793950"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Amrakdow"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WW91ciBuZXR3b3JrIGhhcyBiZWVuIGJyZWFjaGVkIGJ5IEthcm1hIHJhbnNvbXdhcmUgZ" wide //weight: 1
        $x_1_2 = "aaa_TouchMeNot_.txt" wide //weight: 1
        $x_1_3 = "-CYPHEREDDD.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

