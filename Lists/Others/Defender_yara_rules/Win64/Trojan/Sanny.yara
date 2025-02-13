rule Trojan_Win64_Sanny_A_2147730855_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sanny.A"
        threat_id = "2147730855"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sanny"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SbVIn=BU/dqNP2kWw0oCrm9xaJ3tZX6OpFc7Asi4lvuhf-TjMLRQ5GKeEHYgD1yz8" ascii //weight: 1
        $x_1_2 = "taskkill /im cliconfg.exe /f" ascii //weight: 1
        $x_1_3 = "del /f /q NTWDBLIB.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

